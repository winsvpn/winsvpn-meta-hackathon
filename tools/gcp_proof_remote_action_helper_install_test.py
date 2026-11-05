#!/usr/bin/env python3
"""No-network tests for authenticated remote proof-action helper install."""

from __future__ import annotations

import contextlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Iterator, Mapping
from unittest import mock


TOOLS = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REMOTE = load_module(
    "gcp_proof_remote_action_helper_install_subject", TOOLS / "gcp_proof_remote_install.py"
)
ACTION = load_module(
    "gcp_proof_remote_action_helper_install_action", TOOLS / "gcp_proof_remote_action.py"
)
FIXTURES = load_module(
    "gcp_proof_remote_action_helper_install_fixtures",
    TOOLS / "gcp_proof_remote_install_test.py",
)


class _RootOwnedStat:
    def __init__(self, inner: os.stat_result) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        if name in {"st_uid", "st_gid"}:
            return 0
        return getattr(self._inner, name)


@contextlib.contextmanager
def _as_root_owned(*paths: Path) -> Iterator[None]:
    wanted = {os.path.abspath(os.fspath(path)) for path in paths}
    real_lstat = os.lstat
    real_fstat = os.fstat
    real_stat = os.stat

    def _matches(info: os.stat_result) -> bool:
        for path in wanted:
            try:
                current = real_lstat(path)
            except OSError:
                continue
            if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                return True
        return False

    def fake_lstat(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> Any:
        info = real_lstat(path, *args, **kwargs)
        if os.path.abspath(os.fspath(path)) in wanted or _matches(info):
            return _RootOwnedStat(info)
        return info

    def fake_fstat(fd: int) -> Any:
        info = real_fstat(fd)
        if _matches(info):
            return _RootOwnedStat(info)
        return info

    def fake_stat(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> Any:
        info = real_stat(path, *args, **kwargs)
        if _matches(info):
            return _RootOwnedStat(info)
        return info

    with mock.patch("os.lstat", fake_lstat), mock.patch("os.fstat", fake_fstat), mock.patch(
        "os.stat", fake_stat
    ), mock.patch.object(REMOTE.os, "lstat", fake_lstat), mock.patch.object(
        REMOTE.os, "fstat", fake_fstat
    ), mock.patch.object(REMOTE.os, "stat", fake_stat):
        yield


def _complete_kwargs(
    bound: Mapping[str, Any],
    record: Mapping[str, Any],
    **overrides: Any,
) -> dict[str, Any]:
    kwargs = {
        "expected_sha256": bound["sha256"],
        "expected_bytes": bound["bytes"],
        "expected_mode": REMOTE.REMOTE_ACTION_HELPER_INSTALL_MODE,
        "role": "control",
        "fleet_id": "proof-fleet-20260823",
        "instance": "proof-control-a1",
        "candidate_id": record["candidate_id"],
        "source_path": FIXTURES.HELPER_PATH,
    }
    kwargs.update(overrides)
    return kwargs


def _install(
    extracted: Path,
    record: dict[str, Any],
    destination: Path,
    identity_path: Path,
    *,
    as_root: bool = True,
    **overrides: Any,
) -> dict[str, Any]:
    kwargs = {
        "role": "control",
        "fleet_id": "proof-fleet-20260823",
        "instance": "proof-control-a1",
        "candidate_id": record["candidate_id"],
        "destination": destination,
        "identity_path": identity_path,
    }
    kwargs.update(overrides)
    root_ctx = _as_root_owned(destination, identity_path) if as_root else contextlib.nullcontext()
    with root_ctx, mock.patch.object(REMOTE.os, "chown"), mock.patch.object(
        REMOTE.os, "fchown"
    ), mock.patch.object(REMOTE.subprocess, "run") as run:
        bound = REMOTE.install_remote_action_helper(extracted, record, **kwargs)
        run.assert_not_called()
    return bound


def _try_grant_write_acl(path: Path) -> bool:
    if sys.platform == "darwin":
        result = subprocess.run(
            ["chmod", "+a", "everyone allow write", os.fspath(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    setfacl = shutil.which("setfacl")
    if not setfacl:
        return False
    result = subprocess.run(
        [setfacl, "-m", "u:nobody:w", os.fspath(path)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


class RemoteActionHelperInstallTests(unittest.TestCase):
    def test_installs_exact_manifest_bytes_as_root_owned_nonwritable_executable(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(extracted, record, destination, identity_path)
            self.assertEqual(destination.read_bytes(), files[FIXTURES.HELPER_PATH])
            self.assertEqual(REMOTE.sha256_bytes(destination.read_bytes()), bound["sha256"])
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode) & 0o222, 0)
            self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o400)
            identity = REMOTE.strict_json(identity_path.read_bytes(), "identity")
            info = destination.lstat()
            self.assertEqual(identity["role"], "control")
            self.assertEqual(identity["fleet_id"], "proof-fleet-20260823")
            self.assertEqual(identity["instance"], "proof-control-a1")
            self.assertEqual(identity["candidate_id"], record["candidate_id"])
            self.assertEqual(
                identity["required_roles"], ["control", "data-cover", "data-winn3"]
            )
            self.assertEqual(identity["source_path"], FIXTURES.HELPER_PATH)
            self.assertEqual(identity["path"], os.fspath(destination))
            self.assertEqual(identity["st_dev"], info.st_dev)
            self.assertEqual(identity["st_ino"], info.st_ino)
            self.assertEqual(identity_path.read_bytes(), REMOTE.canonical_bytes(identity))
            self.assertFalse((root / "state" / "remote-action-state.json").exists())
            self.assertFalse((root / "state" / "fleet-binding.json").exists())
            self.assertFalse((root / "state" / "winn3-descriptor.json").exists())
            self.assertFalse((root / "nft").exists())

    def test_path_hash_mode_substitution_and_partial_install_fail(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            helper = extracted.joinpath(*PurePosixPath(FIXTURES.HELPER_PATH).parts)

            helper.write_bytes(b"#!/usr/bin/python3\nsubstituted-helper\n")
            os.chmod(helper, 0o755)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "SHA-256|not bound"):
                _install(extracted, record, destination, identity_path)
            self.assertFalse(destination.exists())
            self.assertFalse(identity_path.exists())

            helper.write_bytes(files[FIXTURES.HELPER_PATH])
            os.chmod(helper, 0o644)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "path/hash/mode"):
                _install(extracted, record, destination, identity_path)
            self.assertFalse(destination.exists())
            self.assertFalse(identity_path.exists())

            os.chmod(helper, 0o755)
            moved = helper.with_name("evil.py")
            helper.rename(moved)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unreadable|not bound"):
                _install(extracted, record, destination, identity_path)
            self.assertFalse(destination.exists())
            self.assertFalse(identity_path.exists())
            moved.rename(helper)

            bound = _install(extracted, record, destination, identity_path)
            identity_path.unlink()
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete"):
                _install(extracted, record, destination, identity_path)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete"):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )
            identity_path.write_bytes(b"{}\n")
            os.chmod(identity_path, 0o400)
            destination.unlink()
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete"):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )

    def test_unexpected_role_and_stale_identity_are_refused(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unexpected role"):
                _install(extracted, record, destination, identity_path, role="core")
            self.assertFalse(destination.exists())
            bound = _install(extracted, record, destination, identity_path)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "stale"):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    candidate_id="a" * 64,
                )
            self.assertEqual(destination.read_bytes(), files[FIXTURES.HELPER_PATH])
            extra = destination.with_name(destination.name + ".bak")
            extra.write_bytes(b"extra-helper-state\n")
            with _as_root_owned(destination, identity_path), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "extra"
            ):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )

    def test_manifest_install_path_and_role_list_substitution_fail_closed(self) -> None:
        helper = dict(FIXTURES.sample_manifest()["remote_action_helper"])
        helper["install_path"] = "/tmp/winsvpn-gcp-proof-remote"
        record = FIXTURES.sample_manifest(remote_action_helper=helper)
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = FIXTURES.write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not bound"):
                REMOTE._load_manifest(path, sidecar, digest)
        helper = dict(FIXTURES.sample_manifest()["remote_action_helper"])
        helper["required_roles"] = ["control", "data-winn3"]
        record = FIXTURES.sample_manifest(remote_action_helper=helper)
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = FIXTURES.write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not bound"):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_path_swap_and_cross_role_receipt_reuse_fail(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(extracted, record, destination, identity_path)
            alt = destination.parent / "swapped-helper"
            alt.write_bytes(destination.read_bytes())
            os.chmod(alt, 0o555)
            with _as_root_owned(alt, identity_path), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "stale|not bound"
            ):
                REMOTE.require_complete_remote_action_helper(
                    alt,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )
            alt.unlink()
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "stale"):
                _install(
                    extracted,
                    record,
                    destination,
                    identity_path,
                    role="data-winn3",
                )

    def test_hardlink_and_symlink_helper_or_receipt_fail(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(extracted, record, destination, identity_path)
            linked = destination.parent / "helper-hardlink"
            os.link(destination, linked)
            with _as_root_owned(destination, identity_path), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "single-link|unsafe|not bound"
            ):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )
            linked.unlink()
            real = destination.with_name(destination.name + ".real")
            destination.rename(real)
            destination.symlink_to(real)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete|unsafe"):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )
            destination.unlink()
            real.rename(destination)
            ident_real = identity_path.with_name(identity_path.name + ".real")
            identity_path.rename(ident_real)
            identity_path.symlink_to(ident_real)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete|unsafe"):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )

    def test_post_check_content_swap_and_finalize_recheck_fail(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(extracted, record, destination, identity_path)
            os.chmod(destination, 0o755)
            destination.write_bytes(b"#!/usr/bin/python3\nswapped-after-check\n")
            os.chmod(destination, 0o555)
            with _as_root_owned(destination, identity_path), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "SHA-256|not bound|stale"
            ):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )

    def test_same_digest_wrong_inode_is_refused(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(extracted, record, destination, identity_path)
            original = destination.lstat()
            clone = destination.with_name(destination.name + ".clone")
            clone.write_bytes(destination.read_bytes())
            os.chmod(clone, 0o555)
            destination.unlink()
            clone.rename(destination)
            self.assertEqual(destination.read_bytes(), files[FIXTURES.HELPER_PATH])
            self.assertNotEqual(destination.lstat().st_ino, original.st_ino)
            with _as_root_owned(destination, identity_path), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "stale|inode"
            ):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )

    def test_same_digest_inode_swap_during_write_is_refused(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            real_replace = os.replace

            def swap_helper(src: str, dst: str, *args: Any, **kwargs: Any) -> None:
                real_replace(src, dst, *args, **kwargs)
                if dst != destination.name:
                    return
                payload = destination.read_bytes()
                clone = destination.with_name(destination.name + ".clone")
                clone.write_bytes(payload)
                os.chmod(clone, 0o555)
                destination.unlink()
                clone.rename(destination)

            with mock.patch.object(REMOTE.os, "replace", swap_helper), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "inode|not bound|substituted"
            ):
                _install(extracted, record, destination, identity_path)

    def test_wrong_uid_gid_is_refused(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(extracted, record, destination, identity_path)
            info = destination.lstat()
            self.assertNotEqual(info.st_uid, 0)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "ownership or mode"):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )

    def test_effective_writability_and_acl_fail_if_applicable(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "libexec" / "winsvpn-gcp-proof-remote"
            identity_path = root / "state" / "remote-action-helper.json"
            FIXTURES.write_extracted_tree(extracted, record, files)
            bound = _install(extracted, record, destination, identity_path)
            os.chmod(destination, 0o755)
            with _as_root_owned(destination, identity_path), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "ownership or mode|writable"
            ):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )
            os.chmod(destination, 0o555)
            os.chmod(destination.parent, 0o777)
            with _as_root_owned(destination, identity_path), self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "directory is writable"
            ):
                REMOTE.require_complete_remote_action_helper(
                    destination,
                    identity_path,
                    **_complete_kwargs(bound, record),
                )
            os.chmod(destination.parent, 0o755)
            if _try_grant_write_acl(destination):
                with _as_root_owned(destination, identity_path), self.assertRaisesRegex(
                    REMOTE.RemoteInstallError, "ACL|writable"
                ):
                    REMOTE.require_complete_remote_action_helper(
                        destination,
                        identity_path,
                        **_complete_kwargs(bound, record),
                    )

    def test_test_only_host_and_mocked_ownership_cannot_emit_production_evidence(self) -> None:
        record = FIXTURES.sample_manifest()
        files = FIXTURES.sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            FIXTURES.write_extracted_tree(extracted, record, files)
            production_dest = Path(REMOTE.REMOTE_ACTION_HELPER_INSTALL_PATH)
            production_ident = REMOTE.REMOTE_ACTION_HELPER_IDENTITY_PATH
            self.assertNotEqual(os.geteuid(), 0)
            with self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "test-only host cannot emit production evidence"
            ):
                REMOTE.install_remote_action_helper(
                    extracted,
                    record,
                    role="control",
                    fleet_id="proof-fleet-20260823",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    destination=production_dest,
                    identity_path=production_ident,
                )
            with self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "test-only host cannot emit production evidence"
            ):
                REMOTE.require_complete_remote_action_helper(
                    production_dest,
                    production_ident,
                    expected_sha256=record["remote_action_helper"]["sha256"],
                    expected_bytes=record["remote_action_helper"]["bytes"],
                    expected_mode=REMOTE.REMOTE_ACTION_HELPER_INSTALL_MODE,
                    role="control",
                    fleet_id="proof-fleet-20260823",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    source_path=FIXTURES.HELPER_PATH,
                )
            mixed_ident = root / "state" / "remote-action-helper.json"
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "production paths are not bound"):
                REMOTE.install_remote_action_helper(
                    extracted,
                    record,
                    role="control",
                    fleet_id="proof-fleet-20260823",
                    instance="proof-control-a1",
                    candidate_id=record["candidate_id"],
                    destination=production_dest,
                    identity_path=mixed_ident,
                )


class RemoteActionHelperResponseBindingTests(unittest.TestCase):
    def test_remote_action_helper_constants_are_bound_to_install_contract(self) -> None:
        self.assertEqual(ACTION.INSTALL_PATH, REMOTE.REMOTE_ACTION_HELPER_INSTALL_PATH)
        self.assertEqual(ACTION.RESPONSE_CONTRACT, REMOTE.REMOTE_ACTION_HELPER_CONTRACT)
        self.assertEqual(ACTION.HELPER_IDENTITY_PATH, os.fspath(REMOTE.REMOTE_ACTION_HELPER_IDENTITY_PATH))
        self.assertEqual(ACTION.HELPER_IDENTITY_CONTRACT, REMOTE.REMOTE_ACTION_HELPER_IDENTITY_CONTRACT)
        self.assertEqual(ACTION.HELPER_IDENTITY_KIND, REMOTE.KIND_HELPER_IDENTITY)
        self.assertEqual(ACTION.HELPER_SOURCE_PATH, REMOTE.REMOTE_ACTION_HELPER_PATH)
        self.assertEqual(ACTION.HELPER_INSTALL_MODE, REMOTE.REMOTE_ACTION_HELPER_INSTALL_MODE)
        self.assertEqual(tuple(ACTION.HELPER_REQUIRED_ROLES), REMOTE.REMOTE_ACTION_HELPER_REQUIRED_ROLES)
        self.assertEqual(ACTION.HELPER_IDENTITY_KEYS, REMOTE.REMOTE_ACTION_HELPER_IDENTITY_KEYS)
        self.assertIn(
            ('RESPONSE_CONTRACT = "' + ACTION.RESPONSE_CONTRACT + '"').encode("ascii"),
            Path(ACTION.__file__).read_bytes(),
        )
        self.assertIn(
            ('INSTALL_PATH = "' + ACTION.INSTALL_PATH + '"').encode("ascii"),
            Path(ACTION.__file__).read_bytes(),
        )

    def test_remote_action_refuses_cross_role_helper_identity_receipt(self) -> None:
        host_files = {
            ACTION.INSTALL_PATH: b"#!/usr/bin/python3\nfixture-helper\n",
        }
        payload = host_files[ACTION.INSTALL_PATH]
        identity = {
            "bytes": len(payload),
            "candidate_id": "d" * 64,
            "contract": ACTION.HELPER_IDENTITY_CONTRACT,
            "fleet_id": "123456789abc",
            "instance": "proof-control-a1",
            "kind": ACTION.HELPER_IDENTITY_KIND,
            "mode": ACTION.HELPER_INSTALL_MODE,
            "path": ACTION.INSTALL_PATH,
            "required_roles": list(ACTION.HELPER_REQUIRED_ROLES),
            "role": "data-winn3",
            "schema_version": 1,
            "sha256": ACTION.sha256_bytes(payload),
            "source_path": ACTION.HELPER_SOURCE_PATH,
            "st_dev": 1,
            "st_ino": 1,
        }

        class Host:
            TEST_ONLY = True
            files = host_files

            def hash_executable(self, path: str) -> str:
                return ACTION.sha256_bytes(self.files[path])

            def read_file(self, path: str) -> bytes:
                if path == ACTION.HELPER_IDENTITY_PATH:
                    return ACTION.canonical_bytes(identity)
                return self.files[path]

            def require_helper_identity_binding(self, record: dict) -> None:
                return None

        request = {
            "role": "control",
            "phase": ACTION.PHASE_EXERCISE,
            "action": "route-decision",
            "fleet_id": "123456789abc",
            "instance": "proof-control-a1",
        }
        with self.assertRaisesRegex(ACTION.RemoteActionError, "stale"):
            ACTION.collect_helper_hashes(Host(), request)


if __name__ == "__main__":
    unittest.main()
