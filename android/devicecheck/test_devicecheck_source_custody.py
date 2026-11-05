#!/usr/bin/env python3
"""Focused hostile tests for DeviceCheck source custody.

These tests use only temporary fixtures.  They do not invoke sudo, touch
/Library/WinsVPN, run Gradle, run Go, access a device, or provision a snapshot
in the owner authority.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import devicecheck_source_custody as custody


def _external_test_temp_root() -> Path:
    repository = Path(__file__).resolve().parents[2]
    external_parent = repository.parent.resolve(strict=True)
    if not external_parent.is_dir():
        raise RuntimeError("DeviceCheck test fixture parent is not a directory")
    return external_parent


class DeviceCheckSourceCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._suite_temp = tempfile.TemporaryDirectory(
            prefix=".wins-devicecheck-custody-suite-",
            dir=_external_test_temp_root(),
        )
        suite_root = Path(cls._suite_temp.name).resolve(strict=True)
        watched_source = Path(__file__).resolve().parents[2]
        if (
            suite_root == watched_source
            or suite_root in watched_source.parents
            or watched_source in suite_root.parents
        ):
            cls._suite_temp.cleanup()
            raise RuntimeError("test fixtures entered the watched source ancestry")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._suite_temp.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="wins-devicecheck-custody-",
            dir=self._suite_temp.name,
        )
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self._write("src/alpha.txt", b"alpha\n")
        self._write("src/nested/beta.txt", b"beta\n")
        self._write("control.sh", b"#!/bin/sh\nexit 0\n", mode=0o755)
        self.module_cache = self.root / "module-cache"
        self.module_cache.mkdir()
        self._create_production_source_fixture()
        self._git_init()
        self.original_constants = {
            name: getattr(custody, name)
            for name in (
                "AUTHORITY_ROOT",
                "SOURCE_AUTHORITY_RELATIVE",
                "SNAPSHOT_BASE_RELATIVE",
                "MANIFEST_BASE_RELATIVE",
                "DEFAULT_SNAPSHOT",
                "DEFAULT_MANIFEST",
                "OWNER_AUTHORITY_PATH",
                "RELEASE_PYTHON_PATH",
                "LOADER_PATH",
                "CONTROLLER_PATH",
                "OWNER_SIGNER_CERTIFICATE_PATH",
                "BUILD_WORKSPACE_ROOT",
                "BUILD_CACHE_ROOT",
                "EXPECTED_OWNER_AUTHORITY_SHA256",
            )
        }
        custody.AUTHORITY_ROOT = self.root / "external-owner"
        custody.SOURCE_AUTHORITY_RELATIVE = "devicecheck-v3"
        custody.SNAPSHOT_BASE_RELATIVE = "devicecheck-v3/snapshots/sha256"
        custody.MANIFEST_BASE_RELATIVE = "devicecheck-v3/manifests/sha256"
        custody.DEFAULT_SNAPSHOT = custody.AUTHORITY_ROOT / custody.SNAPSHOT_BASE_RELATIVE
        custody.DEFAULT_MANIFEST = custody.AUTHORITY_ROOT / custody.MANIFEST_BASE_RELATIVE
        custody.OWNER_AUTHORITY_PATH = custody.AUTHORITY_ROOT / "authority.json"
        custody.RELEASE_PYTHON_PATH = (
            custody.AUTHORITY_ROOT / "ReleasePython/3.14.7/launcher/python3"
        )
        custody.LOADER_PATH = custody.AUTHORITY_ROOT / "loader.py"
        custody.CONTROLLER_PATH = custody.AUTHORITY_ROOT / "controller.py"
        custody.OWNER_SIGNER_CERTIFICATE_PATH = custody.AUTHORITY_ROOT / "owner.x509.pem"
        custody.BUILD_WORKSPACE_ROOT = self.root / "private-build-workspace"
        custody.BUILD_CACHE_ROOT = self.root / "private-build-cache"
        self.manifest = custody.build_manifest(
            self.repo,
            self.commit,
            module_cache=self.module_cache,
        )
        self.snapshot = custody.AUTHORITY_ROOT / self.manifest["authority"]["snapshot"]
        self.manifest_path = custody._manifest_path_for_digest(
            custody.manifest_sha256(self.manifest)
        )
        self._create_external_authority()

    def tearDown(self) -> None:
        for name, value in self.original_constants.items():
            setattr(custody, name, value)
        self.temp.cleanup()

    def _create_external_authority(self) -> None:
        for item in self.manifest["closure"]["files"]:
            source = self.repo / item["path"]
            target = self.snapshot / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(0o444)
        for directory in sorted(
            (item for item in self.snapshot.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        self.snapshot.chmod(0o555)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_bytes(custody.manifest_bytes(self.manifest))
        self.manifest_path.chmod(0o444)
        fixed_files = {
            "release_python": (custody.RELEASE_PYTHON_PATH, b"fixture release python"),
            "loader": (custody.LOADER_PATH, b"fixture loader"),
            "controller": (custody.CONTROLLER_PATH, b"fixture controller"),
            "owner_signer_certificate": (
                custody.OWNER_SIGNER_CERTIFICATE_PATH,
                b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            ),
        }
        records = {}
        for role, (path, raw) in fixed_files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o555 if role == "release_python" else 0o444)
            records[role] = {
                "path": str(path),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
        manifest_raw = self.manifest_path.read_bytes()
        records["source_manifest"] = {
            "path": str(self.manifest_path),
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "size_bytes": len(manifest_raw),
        }
        authority = {
            "schema_version": 4,
            "contract": custody.OWNER_AUTHORITY_CONTRACT,
            **records,
            "source_snapshot": {
                "path": str(self.snapshot),
                "closure_sha256": self.manifest["closure"]["sha256"],
            },
            "build": {
                "build_uid": os.getuid() or 501,
                "build_gid": os.getgid() or 20,
                "workspace_root": str(custody.BUILD_WORKSPACE_ROOT),
                "cache_root": str(custody.BUILD_CACHE_ROOT),
                "workspace_mode": "0700",
                "cache_mode": "0700",
                "fresh_workspace_required": True,
                "handoff_contract": custody.BUILD_HANDOFF_CONTRACT,
                "atomic_publication_contract": custody.ATOMIC_PUBLICATION_CONTRACT,
            },
            "authorization": {
                "authorization_id": hashlib.sha256(b"fixture authorization").hexdigest(),
                "nonce": hashlib.sha256(b"fixture nonce").hexdigest(),
                "sequence": 1,
            },
            "consumer": {
                "contract": custody.BUILD_HANDOFF_CONTRACT,
                "status": custody.CONSUMER_STATUS,
            },
            "owner_signer_sha256": hashlib.sha256(b"\x01\x02\x03").hexdigest(),
            "secret_material_redacted": True,
        }
        raw = custody._canonical_bytes(authority)
        custody.OWNER_AUTHORITY_PATH.write_bytes(raw)
        custody.OWNER_AUTHORITY_PATH.chmod(0o444)
        custody.EXPECTED_OWNER_AUTHORITY_SHA256 = hashlib.sha256(raw).hexdigest()

    def _write(self, relative: str, data: bytes, *, mode: int = 0o644) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _capture_authenticated(
        self,
        root: Path,
        relative: str,
        expected: bytes,
    ) -> custody._CapturedFile:
        return custody.capture_file(
            root,
            relative,
            expected_sha256=hashlib.sha256(expected).hexdigest(),
            expected_size=len(expected),
        )

    def _create_production_source_fixture(self) -> None:
        explicit = (
            custody.DEVICECHECK_CONTROL_FILES
            + custody.ANDROID_CONTROL_FILES
            + custody.DEVICECHECK_EXPLICIT_SOURCE_FILES
        )
        for relative in explicit:
            if not (self.repo / relative).exists():
                self._write(relative, f"fixture:{relative}\n".encode("ascii"))
        for name in custody.SHIPPING_APP_SOURCE_FILES:
            relative = f"android/app/src/main/kotlin/org/winsvpn/app/{name}"
            self._write(relative, f"fixture:{relative}\n".encode("ascii"))
        for relative in custody.DEVICECHECK_TREE_ROOTS:
            marker = f"{relative}/fixture-source.txt"
            if not (self.repo / marker).exists():
                self._write(marker, f"fixture:{relative}\n".encode("ascii"))
        for relative in custody.GO_SUM_FILES:
            self._write(relative, b"")

    def _git_init(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "-c",
                "user.name=DeviceCheck Test",
                "-c",
                "user.email=devicecheck@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()

    def test_manifest_is_content_addressed_bounded_and_git_bound(self) -> None:
        custody.validate_manifest(self.manifest)
        closure = self.manifest["closure"]
        self.assertEqual(closure["files"], sorted(closure["files"], key=lambda item: item["path"].encode()))
        self.assertEqual(closure["sha256"], custody.closure_digest(closure["files"], closure["directories"]))
        self.assertEqual(self.manifest["reviewed"]["commit"], self.commit)
        self.assertEqual(
            [item["path"] for item in self.manifest["reviewed"]["files"]],
            [
                item["path"]
                for item in closure["files"]
                if not item["path"].startswith("module-cache/")
            ],
        )
        self.assertEqual(
            self.manifest["authority"]["snapshot"],
            custody._snapshot_relative_for_digest(closure["sha256"]),
        )
        self.assertEqual(
            closure["total_bytes"],
            sum(item["bytes"] for item in closure["files"]),
        )
        self.assertLess(len(custody.manifest_bytes(self.manifest)), custody.MAX_MANIFEST_BYTES)

    def test_descriptor_read_rejects_symlink(self) -> None:
        (self.repo / "src/alpha.txt").unlink()
        (self.repo / "src/alpha.txt").symlink_to(self.repo / "src/nested/beta.txt")
        with self.assertRaisesRegex(custody.CustodyError, "symlink"):
            self._capture_authenticated(self.repo, "src/alpha.txt", b"alpha\n")

    def test_descriptor_read_rejects_hardlink(self) -> None:
        os.link(self.repo / "src/alpha.txt", self.repo / "src/hardlink.txt")
        with self.assertRaisesRegex(custody.CustodyError, "one-link"):
            self._capture_authenticated(self.repo, "src/hardlink.txt", b"alpha\n")

    def test_tree_walk_rejects_symlinked_directory(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "escape.txt").write_bytes(b"escape")
        (self.repo / "src/escape").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(custody.CustodyError, "symlink"):
            custody._capture_tree(self.repo / "src", "src")

    def test_root_open_never_uses_pathname_realpath_authority(self) -> None:
        with mock.patch.object(
            custody.os.path,
            "realpath",
            side_effect=AssertionError("pathname realpath authority was used"),
        ):
            captured = self._capture_authenticated(
                self.repo,
                "control.sh",
                b"#!/bin/sh\nexit 0\n",
            )
        self.assertEqual(captured.data, b"#!/bin/sh\nexit 0\n")

    def test_transient_symlink_between_component_stat_and_open_is_rejected(self) -> None:
        hostile = self.root / "hostile-repository"
        hostile.mkdir()
        (hostile / "control.sh").write_bytes(b"hostile via transient symlink\n")
        authentic = self.root / "repo.authentic"
        original_open = custody.os.open
        substituted = False

        def open_with_transient_symlink(path, flags, *args, **kwargs):
            nonlocal substituted
            if not substituted and path == "repo" and kwargs.get("dir_fd") is not None:
                substituted = True
                self.repo.rename(authentic)
                self.repo.symlink_to(hostile, target_is_directory=True)
                try:
                    return original_open(path, flags, *args, **kwargs)
                finally:
                    self.repo.unlink()
                    authentic.rename(self.repo)
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(custody.os, "open", side_effect=open_with_transient_symlink):
            with self.assertRaisesRegex(custody.CustodyError, "O_NOFOLLOW|changed"):
                self._capture_authenticated(
                    self.repo,
                    "control.sh",
                    b"#!/bin/sh\nexit 0\n",
                )
        self.assertTrue(substituted)
        self.assertTrue(self.repo.is_dir())
        self.assertFalse(self.repo.is_symlink())
        self.assertFalse(authentic.exists())

    def test_descendant_mutation_before_file_watch_is_authenticated_and_rejected(self) -> None:
        target = self.repo / "control.sh"
        authentic = target.read_bytes()
        original_read_file_at = custody._read_file_at
        mutated = False

        def read_after_mutation(*args, **kwargs):
            nonlocal mutated
            if not mutated and args[1] == "control.sh":
                mutated = True
                target.write_bytes(b"hostile-before-file-watch\n")
                target.write_bytes(authentic)
                target.chmod(0o755)
                return original_read_file_at(*args, **kwargs)
            return original_read_file_at(*args, **kwargs)

        with mock.patch.object(
            custody,
            "_read_file_at",
            side_effect=read_after_mutation,
        ):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "authenticated manifest|authenticated SHA-256|namespace or identity change",
            ):
                self._capture_authenticated(self.repo, "control.sh", authentic)
        self.assertTrue(mutated)
        self.assertEqual(target.read_bytes(), authentic)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_open_root_failure_closes_each_owned_descriptor_once(self) -> None:
        hostile_root = self.root / "fd-cleanup"
        hostile_root.mkdir()
        (hostile_root / "link").symlink_to(self.repo, target_is_directory=True)
        original_close = custody.os.close
        closed: list[int] = []

        def record_close(fd: int) -> None:
            closed.append(fd)
            original_close(fd)

        with mock.patch.object(custody.os, "close", side_effect=record_close):
            with self.assertRaises(custody.CustodyError):
                custody._open_root(hostile_root / "link", "hostile cleanup root")
        self.assertGreater(len(closed), 1)
        self.assertEqual(closed, list(dict.fromkeys(closed)))

    def test_closure_paths_closes_root_watcher_and_all_ancestor_descriptors(self) -> None:
        before = set(os.listdir("/dev/fd"))
        for _ in range(5):
            custody.closure_paths(self.repo, module_cache=self.module_cache)
        after = set(os.listdir("/dev/fd"))
        self.assertEqual(after, before)

    def test_unrelated_higher_ancestor_churn_before_watch_is_fail_closed(self) -> None:
        original_open = custody.os.open
        churned = False

        def open_with_churn(path, flags, *args, **kwargs):
            nonlocal churned
            if not churned and path == self.root.name and kwargs.get("dir_fd") is not None:
                churned = True
                unrelated = self.root / "unrelated-churn"
                unrelated.write_bytes(b"unrelated\n")
                unrelated.unlink()
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(custody.os, "open", side_effect=open_with_churn):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "changed while it was opened|changed before custody|namespace or identity change",
            ):
                self._capture_authenticated(self.repo, "control.sh", b"#!/bin/sh\nexit 0\n")
        self.assertTrue(churned)

    def test_exact_swap_restore_between_stat_and_ancestor_open_is_rejected(self) -> None:
        original_open = custody.os.open
        swapped = False

        def open_with_exact_restore(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and path == self.root.name and kwargs.get("dir_fd") is not None:
                swapped = True
                authentic = self.root.with_name(self.root.name + ".authentic")
                hostile = self.root.with_name(self.root.name + ".hostile")
                self.root.rename(authentic)
                self.root.mkdir()
                self.root.rename(hostile)
                authentic.rename(self.root)
                hostile.rmdir()
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(custody.os, "open", side_effect=open_with_exact_restore):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "changed while it was opened|namespace or identity change|changed before custody",
            ):
                self._capture_authenticated(self.repo, "control.sh", b"#!/bin/sh\nexit 0\n")
        self.assertTrue(swapped)
        self.assertFalse(self.root.with_name(self.root.name + ".authentic").exists())
        self.assertFalse(self.root.with_name(self.root.name + ".hostile").exists())

    def test_exact_swap_restore_before_child_watch_registration_is_rejected(self) -> None:
        original_register = custody._register_directory_watch
        swapped = False

        def register_with_exact_restore(
            watcher,
            fd: int,
            label: str,
            *,
            namespace: bool = True,
        ) -> None:
            nonlocal swapped
            if not swapped and label.endswith(str(self.root)):
                swapped = True
                authentic = self.root.with_name(self.root.name + ".authentic")
                hostile = self.root.with_name(self.root.name + ".hostile")
                self.root.rename(authentic)
                self.root.mkdir()
                self.root.rename(hostile)
                authentic.rename(self.root)
                hostile.rmdir()
            original_register(watcher, fd, label, namespace=namespace)

        with mock.patch.object(
            custody,
            "_register_directory_watch",
            side_effect=register_with_exact_restore,
        ):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "namespace or identity change|changed before custody",
            ):
                self._capture_authenticated(self.repo, "control.sh", b"#!/bin/sh\nexit 0\n")
        self.assertTrue(swapped)
        self.assertFalse(self.root.with_name(self.root.name + ".authentic").exists())
        self.assertFalse(self.root.with_name(self.root.name + ".hostile").exists())

    def test_exact_distant_ancestor_swap_restore_is_rejected(self) -> None:
        nested = self.root / "higher-a" / "higher-b" / "higher-c" / "target"
        nested.mkdir(parents=True)
        (nested / "proof.txt").write_bytes(b"authentic\n")
        original_open = custody.os.open
        swapped = False

        def open_with_exact_restore(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and path == "higher-a" and kwargs.get("dir_fd") is not None:
                swapped = True
                target = self.root / "higher-a"
                authentic = self.root / "higher-a.authentic"
                hostile = self.root / "higher-a.hostile"
                target.rename(authentic)
                target.mkdir()
                target.rename(hostile)
                authentic.rename(target)
                hostile.rmdir()
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(custody.os, "open", side_effect=open_with_exact_restore):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "namespace or identity change|changed while it was opened",
            ):
                self._capture_authenticated(nested, "proof.txt", b"authentic\n")
        self.assertTrue(swapped)
        self.assertFalse((self.root / "higher-a.authentic").exists())
        self.assertFalse((self.root / "higher-a.hostile").exists())

    def test_hostile_swap_after_descriptor_read_is_rejected(self) -> None:
        original_read = custody.os.read
        swapped = False

        def read_and_swap(fd: int, size: int) -> bytes:
            nonlocal swapped
            data = original_read(fd, size)
            if data and not swapped:
                swapped = True
                target = self.repo / "control.sh"
                replacement = self.repo / "replacement.sh"
                target.rename(replacement)
                target.write_bytes(b"hostile replacement\n")
            return data

        with mock.patch.object(custody.os, "read", side_effect=read_and_swap):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "changed|namespace or identity change",
            ):
                self._capture_authenticated(self.repo, "control.sh", b"#!/bin/sh\nexit 0\n")

    def test_higher_ancestor_swap_and_restore_is_rejected(self) -> None:
        original_read = custody.os.read
        swapped = False

        def read_with_parent_swap(fd: int, size: int) -> bytes:
            nonlocal swapped
            data = original_read(fd, size)
            if data and not swapped:
                swapped = True
                authentic = self.root / "repo.authentic"
                hostile = self.root / "repo.hostile"
                self.repo.rename(authentic)
                self.repo.mkdir()
                self.repo.rename(hostile)
                authentic.rename(self.repo)
            return data

        with mock.patch.object(custody.os, "read", side_effect=read_with_parent_swap):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "ancestor identity changed|detected ancestor rename|namespace or identity change",
            ):
                self._capture_authenticated(self.repo, "control.sh", b"#!/bin/sh\nexit 0\n")

    def test_git_metadata_inventory_streams_and_enforces_per_file_bound(self) -> None:
        metadata = self.root / "git-metadata-per-file"
        metadata.mkdir()
        (metadata / "oversize.pack").write_bytes(b"x" * 17)
        with mock.patch.object(custody, "MAX_GIT_METADATA_FILE_BYTES", 16):
            with self.assertRaisesRegex(custody.CustodyError, "per-file bound"):
                custody._capture_git_metadata_tree(metadata, "git-metadata")

    def test_git_metadata_inventory_enforces_aggregate_bound(self) -> None:
        metadata = self.root / "git-metadata-aggregate"
        metadata.mkdir()
        (metadata / "one.pack").write_bytes(b"a" * 13)
        (metadata / "two.pack").write_bytes(b"b" * 13)
        with (
            mock.patch.object(custody, "MAX_GIT_METADATA_FILE_BYTES", 16),
            mock.patch.object(custody, "MAX_GIT_METADATA_TOTAL_BYTES", 24),
        ):
            with self.assertRaisesRegex(custody.CustodyError, "aggregate byte bound"):
                custody._capture_git_metadata_tree(metadata, "git-metadata")

    def test_git_metadata_inventory_retains_hash_not_payload(self) -> None:
        metadata = self.root / "git-metadata-streaming"
        metadata.mkdir()
        payload = b"reviewed pack bytes\n"
        (metadata / "reviewed.pack").write_bytes(payload)
        files, _directories = custody._capture_git_metadata_tree(
            metadata,
            "git-metadata",
        )
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["bytes"], len(payload))
        self.assertEqual(files[0]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertNotIn("data", files[0])

    def test_reviewed_git_binding_rejects_metadata_swap_restore(self) -> None:
        original = custody._git_command
        swapped = False

        def command_with_swap(repo: Path, *args: str) -> bytes:
            nonlocal swapped
            output = original(repo, *args)
            if not swapped:
                swapped = True
                authentic = repo / ".git.authentic"
                hostile = repo / ".git.hostile"
                (repo / ".git").rename(authentic)
                (repo / ".git").mkdir()
                (repo / ".git").rename(hostile)
                authentic.rename(repo / ".git")
            return output

        with mock.patch.object(custody, "_git_command", side_effect=command_with_swap):
            with self.assertRaisesRegex(
                custody.CustodyError,
                "identity changed|namespace or identity change",
            ):
                custody.reviewed_git_binding(
                    self.repo,
                    self.commit,
                    required_paths=("control.sh",),
                )

    def test_reviewed_git_binding_rejects_external_object_redirection(self) -> None:
        alternates = self.repo / ".git/objects/info/alternates"
        alternates.write_text(str(self.root / "hostile-objects") + "\n", encoding="ascii")
        with self.assertRaisesRegex(custody.CustodyError, "redirects outside"):
            custody.reviewed_git_binding(
                self.repo,
                self.commit,
                required_paths=("control.sh",),
            )

    def test_reviewed_git_binding_rejects_external_common_directory(self) -> None:
        local_git = self.repo / ".git"
        external_git = self.root / "external-common.git"
        local_git.rename(external_git)
        local_git.mkdir()
        shutil.copy2(external_git / "HEAD", local_git / "HEAD")
        shutil.copy2(external_git / "index", local_git / "index")
        (local_git / "commondir").write_text(str(external_git) + "\n", encoding="ascii")
        try:
            with self.assertRaisesRegex(
                custody.CustodyError,
                "redirects outside|common directory",
            ):
                custody.reviewed_git_binding(
                    self.repo,
                    self.commit,
                    required_paths=("control.sh",),
                )
        finally:
            shutil.rmtree(local_git)
            external_git.rename(local_git)

    def test_reviewed_git_binding_reconciles_git_common_directory_identity(self) -> None:
        original = custody._git_command

        def command_with_external_common_dir(repo: Path, *args: str) -> bytes:
            if args == ("rev-parse", "--git-common-dir"):
                return b"/private/tmp/hostile-common.git\n"
            return original(repo, *args)

        with mock.patch.object(
            custody,
            "_git_command",
            side_effect=command_with_external_common_dir,
        ):
            with self.assertRaisesRegex(custody.CustodyError, "common directory"):
                custody.reviewed_git_binding(
                    self.repo,
                    self.commit,
                    required_paths=("control.sh",),
                )

    def test_duplicate_manifest_path_is_rejected(self) -> None:
        hostile = json.loads(custody.manifest_bytes(self.manifest))
        hostile["closure"]["files"].append(dict(hostile["closure"]["files"][0]))
        with self.assertRaisesRegex(custody.CustodyError, "duplicated"):
            custody.validate_manifest(hostile)

    def test_manifest_requires_exact_git_blob_and_mode_for_every_repo_file(self) -> None:
        hostile = json.loads(custody.manifest_bytes(self.manifest))
        hostile["reviewed"]["files"][0]["object"] = "0" * len(self.commit)
        with self.assertRaisesRegex(custody.CustodyError, "reviewed Git blob"):
            custody.validate_manifest(hostile)

        hostile = json.loads(custody.manifest_bytes(self.manifest))
        current_mode = hostile["reviewed"]["files"][0]["mode"]
        hostile["reviewed"]["files"][0]["mode"] = (
            "100644" if current_mode == "100755" else "100755"
        )
        with self.assertRaisesRegex(custody.CustodyError, "reviewed Git mode"):
            custody.validate_manifest(hostile)

    def test_untracked_or_ignored_closure_input_is_rejected(self) -> None:
        ignored = self.repo / "android/devicecheck/app/src/androidTest/generated.bin"
        ignored.write_bytes(b"generated\n")
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "status.showUntrackedFiles", "no"],
            check=True,
        )
        with self.assertRaisesRegex(custody.CustodyError, "dirty|untracked or ignored"):
            custody.build_manifest(
                self.repo,
                self.commit,
                module_cache=self.module_cache,
            )

    def test_cross_tree_input_is_rejected(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_bytes(b"outside")
        with self.assertRaisesRegex(custody.CustodyError, "outside the allowed source tree"):
            custody._capture_closure(
                self.repo,
                ((outside, "outside.txt"),),
                allowed_roots=(self.repo,),
            )

    def test_reviewed_commit_mismatch_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(custody.CustodyError, "commit mismatch"):
            custody.build_manifest(
                self.repo,
                "0" * 40,
                module_cache=self.module_cache,
            )

    def test_reviewed_source_tree_must_be_clean(self) -> None:
        target = self.repo / "android/devicecheck/app/src/main/AndroidManifest.xml"
        target.write_bytes(b"unreviewed\n")
        with self.assertRaisesRegex(custody.CustodyError, "reviewed Git blob"):
            custody.build_manifest(
                self.repo,
                self.commit,
                module_cache=self.module_cache,
            )

    def test_external_owner_authority_authenticates_fixed_snapshot_and_tools(self) -> None:
        result = custody._load_owner_authority_at(
            custody.OWNER_AUTHORITY_PATH,
            custody.EXPECTED_OWNER_AUTHORITY_SHA256,
            require_owner_custody=False,
        )
        self.assertEqual(result["source_closure_sha256"], self.manifest["closure"]["sha256"])
        self.assertEqual(result["source_snapshot"], str(self.snapshot))
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["consumer_handoff"], "unintegrated")
        self.assertEqual(
            result["owner_signer_sha256"],
            hashlib.sha256(b"\x01\x02\x03").hexdigest(),
        )

    def test_release_python_and_data_authority_paths_are_exact(self) -> None:
        self.assertEqual(
            str(custody.RELEASE_PYTHON_PATH),
            str(custody.AUTHORITY_ROOT / "ReleasePython/3.14.7/launcher/python3"),
        )
        authority = custody.parse_manifest(custody.OWNER_AUTHORITY_PATH.read_bytes())
        custody.validate_owner_authority(authority)
        self.assertEqual(Path(authority["loader"]["path"]), custody.LOADER_PATH)
        self.assertEqual(Path(authority["controller"]["path"]), custody.CONTROLLER_PATH)
        self.assertEqual(authority["build"]["workspace_mode"], "0700")
        self.assertEqual(authority["build"]["cache_mode"], "0700")
        self.assertTrue(authority["build"]["fresh_workspace_required"])
        self.assertEqual(
            authority["build"]["atomic_publication_contract"],
            custody.ATOMIC_PUBLICATION_CONTRACT,
        )

    def test_authority_rejects_held_loader_controller_or_runtime_drift(self) -> None:
        for path in (
            custody.RELEASE_PYTHON_PATH,
            custody.LOADER_PATH,
            custody.CONTROLLER_PATH,
        ):
            with self.subTest(path=path):
                original = path.read_bytes()
                original_mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(0o644)
                path.write_bytes(original + b" drift")
                path.chmod(original_mode)
                try:
                    with self.assertRaisesRegex(custody.CustodyError, "bytes do not match"):
                        custody._load_owner_authority_at(
                            custody.OWNER_AUTHORITY_PATH,
                            custody.EXPECTED_OWNER_AUTHORITY_SHA256,
                            require_owner_custody=False,
                        )
                finally:
                    path.chmod(0o644)
                    path.write_bytes(original)
                    path.chmod(original_mode)

    def test_caller_minted_authority_cannot_replace_reviewed_anchor(self) -> None:
        hostile = self.root / "caller-authority.json"
        hostile.write_bytes(custody.OWNER_AUTHORITY_PATH.read_bytes())
        hostile.chmod(0o444)
        with self.assertRaisesRegex(custody.CustodyError, "path is fixed"):
            custody._load_owner_authority_at(
                hostile,
                custody.EXPECTED_OWNER_AUTHORITY_SHA256,
                require_owner_custody=False,
            )

    def test_missing_external_authority_is_owner_blocked(self) -> None:
        with self.assertRaisesRegex(custody.CustodyError, "OWNER-BLOCKED"):
            custody._load_owner_authority_at(
                custody.OWNER_AUTHORITY_PATH,
                "0" * 64,
                require_owner_custody=False,
            )

    def test_snapshot_symlink_and_hardlink_are_rejected(self) -> None:
        snapshot = self.snapshot
        file_paths = [item["path"] for item in self.manifest["closure"]["files"]]
        target = snapshot / file_paths[0]
        other = snapshot / file_paths[1]
        target.parent.chmod(0o755)
        target.chmod(0o644)
        target.unlink()
        target.symlink_to(other)
        with self.assertRaisesRegex(custody.CustodyError, "symlink"):
            custody.verify_snapshot(self.manifest, snapshot, require_sealed=False)

        target.unlink()
        os.link(other, target)
        with self.assertRaisesRegex(custody.CustodyError, "one-link|hardlink"):
            custody.verify_snapshot(self.manifest, snapshot, require_sealed=False)

    def test_arbitrary_snapshot_and_manifest_paths_are_not_authority(self) -> None:
        outside = self.root / "caller-snapshot"
        outside.mkdir()
        with self.assertRaisesRegex(custody.CustodyError, "content-addressed owner authority"):
            custody.verify_snapshot(self.manifest, outside, require_sealed=False)
        hostile = json.loads(custody.manifest_bytes(self.manifest))
        hostile["authority"]["snapshot"] = "devicecheck-v3/snapshots/sha256/" + "0" * 64
        with self.assertRaisesRegex(custody.CustodyError, "content-addressed closure path"):
            custody.validate_manifest(hostile)

    def test_secret_paths_and_private_key_material_are_rejected(self) -> None:
        for relative, data in (
            ("src/credentials.json", b"{}\n"),
            (
                "src/innocent.txt",
                b"-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n",
            ),
        ):
            with self.subTest(relative=relative):
                self._write(relative, data)
                with self.assertRaisesRegex(custody.CustodyError, "credential|private-key"):
                    custody._capture_tree(self.repo / "src", "src")
                (self.repo / relative).unlink()

    def test_generated_directory_in_source_root_is_rejected(self) -> None:
        generated = self.repo / "src/build"
        generated.mkdir()
        with self.assertRaisesRegex(custody.CustodyError, "ignored or generated"):
            custody._capture_tree(self.repo / "src", "src")

    def test_owner_authority_requires_explicit_unintegrated_consumer(self) -> None:
        authority = custody.parse_manifest(custody.OWNER_AUTHORITY_PATH.read_bytes())
        authority["consumer"]["status"] = "complete"
        with self.assertRaisesRegex(custody.CustodyError, "consumer integration"):
            custody.validate_owner_authority(authority)

    def test_source_modes_are_data_only(self) -> None:
        with self.assertRaisesRegex(custody.CustodyError, "setuid or setgid"):
            custody._require_one_link_regular(
                types.SimpleNamespace(st_mode=stat.S_IFREG | 0o6755, st_nlink=1),
                "hostile source",
            )

    def test_manifest_authoring_provisioning_and_root_helper_are_disabled(self) -> None:
        path = self.root / "authority" / "manifest.json"
        with self.assertRaisesRegex(custody.CustodyError, "verification-only"):
            custody.write_manifest(path, self.manifest)
        with self.assertRaisesRegex(custody.CustodyError, "never provisions"):
            custody.provision_snapshot(self.manifest, self.repo)
        with self.assertRaisesRegex(custody.CustodyError, "no root-helper"):
            custody.owner_provision_command(path, repo=self.repo, helper=self.repo / "mutable.py")
        with self.assertRaisesRegex(custody.CustodyError, "caller-selected manifests"):
            custody.load_manifest(path)

    def test_verifier_has_no_root_provisioner_or_kotlin_hash_substitute(self) -> None:
        source = Path(custody.__file__).read_text(encoding="ascii")
        self.assertNotIn("os.chflags(", source)
        self.assertNotIn("subprocess.call", source)
        self.assertNotIn('"sudo"', source)
        self.assertNotIn("kotlin_source_sha256", source)
        self.assertIn("no root-helper command exists", source)

    def test_production_authentication_never_claims_consumer_handoff(self) -> None:
        with mock.patch.object(custody, "_load_owner_authority_at") as audit:
            audit.return_value = {"production_ready": False}
            with self.assertRaisesRegex(custody.CustodyError, "external authenticated"):
                custody.authenticate_owner_authority()
        audit.assert_called_once_with(
            custody.OWNER_AUTHORITY_PATH,
            custody.EXPECTED_OWNER_AUTHORITY_SHA256,
            require_owner_custody=True,
        )

    def test_strict_json_rejects_duplicate_and_nonfinite_values(self) -> None:
        with self.assertRaisesRegex(custody.CustodyError, "duplicate JSON key"):
            custody.parse_manifest(b'{"x":1,"x":2}\n')
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token):
                with self.assertRaisesRegex(custody.CustodyError, "non-finite"):
                    custody.parse_manifest(b'{"x":' + token + b"}\n")


class DeviceCheckBuildSourceContractTests(unittest.TestCase):
    BUILD_SCRIPT = Path(__file__).with_name("build_devicecheck.sh")
    BLOCKER = (
        "OWNER-BLOCKED: immutable compiler-input handoff is not implemented "
        "by the external controller/loader."
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = cls.BUILD_SCRIPT.read_text(encoding="ascii")

    def test_blocker_follows_held_authority_gate_and_parser_only_selftest(self) -> None:
        fd10 = self.source.index('require_held_path_fd 10 "ReleasePython"')
        fd11 = self.source.index('require_held_path_fd 11 "release loader"')
        fd16 = self.source.index(
            'require_held_path_fd 16 "authority-bound receipt tool"'
        )
        gate = self.source.index(
            '"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate \\\n'
            '  --repo-root "${PROJECT_ROOT}"'
        )
        selftest = self.source.index(
            'if [[ "${WINN_DEVICECHECK_RECEIPT_SELFTEST:-}" == "1" ]]; then'
        )
        selftest_exec = self.source.index(
            'exec "${RELEASE_PYTHON}" -I -S /dev/fd/16 selftest', selftest
        )
        selftest_end = self.source.index("\nfi\n", selftest) + len("\nfi\n")
        blocker = self.source.index(f'echo "{self.BLOCKER}" >&2')
        blocker_exit = self.source.index("\nexit 1\n", blocker)

        self.assertLess(fd10, fd11)
        self.assertLess(fd11, fd16)
        self.assertLess(fd16, gate)
        self.assertLess(gate, selftest)
        self.assertLess(selftest, selftest_exec)
        self.assertLess(selftest_exec, selftest_end)
        self.assertLess(selftest_end, blocker)
        between = self.source[selftest_end:blocker]
        self.assertTrue(
            all(not line.strip() or line.startswith("#") for line in between.splitlines())
        )
        self.assertEqual(
            self.source[blocker:blocker_exit + len("\nexit 1")],
            f'echo "{self.BLOCKER}" >&2\nexit 1',
        )

    def test_mutable_compiler_source_and_output_actions_are_absent(self) -> None:
        blocker = self.source.index(f'echo "{self.BLOCKER}" >&2')
        blocker_exit = self.source.index("\nexit 1\n", blocker)
        executable_source = "\n".join(
            line
            for line in self.source.splitlines()
            if line.strip() and not line.startswith("#")
        )
        actions = {
            "SDK read": 'LOCAL_PROPERTIES="${HERE}/local.properties"',
            "Gradle command": '"${ANDROID_DIR}/gradlew" --project-dir',
            "Go selection": 'GO_BIN="${WINS_GO_BIN:-$(command -v go || true)}"',
            "source copy": 'cp "${SRC}/${name}" "${DST}/${name}"',
            "compiler output directory": 'mkdir -p "${JNI}"',
            "temporary output": 'AAR_ENGINE="$(mktemp',
            "signing decision": 'KEYSTORE="${WINS_ANDROID_KEYSTORE:-}"',
            "producer receipt": "/dev/fd/16 record",
            "device action": 'DEVICES="$("${ADB}" devices)"',
        }
        for label, marker in actions.items():
            with self.subTest(action=label):
                self.assertNotIn(marker, executable_source)
        tail = self.source[blocker_exit + len("\nexit 1\n"):]
        self.assertTrue(
            all(not line.strip() or line.startswith("#") for line in tail.splitlines())
        )

    def test_hostile_environment_strings_and_caller_data_cannot_bypass_exit(self) -> None:
        blocker_script = f'echo "{self.BLOCKER}" >&2\nexit 1\n'
        self.assertNotIn("$", blocker_script)
        hostile = (
            "1",
            "0; exit 0",
            "$(exit 0)",
            "' || exit 0 || '",
            "OWNER-BLOCKED=0",
        )
        for value in hostile:
            environment = {
                **os.environ,
                "WINN_DEVICECHECK_IMMUTABLE_INPUT_HANDOFF": value,
                "WINN_DEVICECHECK_SOURCE_PROBE": value,
                "WINN_DEVICECHECK_GRADLE_PROBE": value,
                "WINN_DEVICECHECK_PRODUCER_ONLY": value,
            }
            with self.subTest(value=value):
                result = subprocess.run(
                    ["bash", "-c", blocker_script, value, "fixture", "/caller/path"],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, f"{self.BLOCKER}\n")

    def test_no_executable_tail_exists_for_shell_bootstrap_to_reach(self) -> None:
        blocker = self.source.index(f'echo "{self.BLOCKER}" >&2')
        blocker_exit = self.source.index("\nexit 1\n", blocker)
        tail = self.source[blocker_exit + len("\nexit 1\n"):]
        forbidden = (
            "gradlew",
            "ndk-build",
            "command -v go",
            "adb",
            "apksigner",
            "mktemp",
            "mkdir",
            "cp ",
            "/dev/fd/16 record",
        )
        executable_tail = "\n".join(
            line for line in tail.splitlines() if line.strip() and not line.startswith("#")
        )
        self.assertEqual(executable_tail, "")
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, executable_tail)


if __name__ == "__main__":
    unittest.main()
