#!/usr/bin/env python3
"""Hostile temp-root tests for the fixed ReleasePython owner transaction."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "macos_release_python_owner_provision.py"
INSTALLER = ROOT / "tools" / "install_macos_release_python_owner_provision.sh"
LAUNCHER_TEST = ROOT / "tools" / "test_macos_release_python_owner_launcher.py"
SPEC = importlib.util.spec_from_file_location(
    "macos_release_python_owner_provision", TOOL
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load owner-provision module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

NOW = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
SEED = bytes.fromhex("1f" * 32)
OTHER_SEED = bytes.fromhex("2e" * 32)


def encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = point
    inverse = pow(z, MODULE._P - 2, MODULE._P)
    affine_x = x * inverse % MODULE._P
    affine_y = y * inverse % MODULE._P
    encoded = affine_y | ((affine_x & 1) << 255)
    return encoded.to_bytes(32, "little")


def public_key(seed: bytes) -> bytes:
    hashed = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(
        bytes([hashed[0] & 248]) + hashed[1:31] + bytes([(hashed[31] & 63) | 64]),
        "little",
    )
    return encode_point(MODULE._mul(MODULE._BASE, scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    hashed = hashlib.sha512(seed).digest()
    scalar_bytes = bytes([hashed[0] & 248]) + hashed[1:31] + bytes(
        [(hashed[31] & 63) | 64]
    )
    scalar = int.from_bytes(scalar_bytes, "little")
    public = encode_point(MODULE._mul(MODULE._BASE, scalar))
    nonce = int.from_bytes(hashlib.sha512(hashed[32:] + message).digest(), "little") % MODULE._L
    encoded_nonce = encode_point(MODULE._mul(MODULE._BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_nonce + public + message).digest(), "little"
    ) % MODULE._L
    signature_scalar = (nonce + challenge * scalar) % MODULE._L
    return encoded_nonce + signature_scalar.to_bytes(32, "little")


class FakeOperations(MODULE.SystemOperations):
    def __init__(self) -> None:
        self.flags: dict[tuple[int, int], int] = {}

    def _key(self, fd: int) -> tuple[int, int]:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino

    def mark(self, path: Path, flags: int) -> None:
        info = os.stat(path, follow_symlinks=False)
        self.flags[(info.st_dev, info.st_ino)] = flags

    def flags_fd(self, fd: int) -> int:
        return self.flags.get(self._key(fd), 0)

    def set_flags_fd(self, fd: int, flags: int) -> None:
        self.flags[self._key(fd)] = flags

    def full_sync(self, fd: int) -> None:
        os.fsync(fd)

    def sync_directory(self, fd: int) -> None:
        os.fsync(fd)

    def rename_exclusive(
        self, source_fd: int, source: str, destination_fd: int, destination: str
    ) -> None:
        os.link(
            source,
            destination,
            src_dir_fd=source_fd,
            dst_dir_fd=destination_fd,
            follow_symlinks=False,
        )
        os.unlink(source, dir_fd=source_fd)


class FakeNativeCapability:
    def __init__(
        self,
        runtime_launcher_sha256: str,
        runtime_python_sha256: str,
        runtime_launcher_tree_sha256: str = "",
    ) -> None:
        self.record = {
            "runtime_launcher_sha256": runtime_launcher_sha256,
            "runtime_python_sha256": runtime_python_sha256,
            "runtime_launcher_tree_sha256": runtime_launcher_tree_sha256,
        }

    def validate(self) -> None:
        return

    def close(self) -> None:
        return


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wins-release-python-owner-", dir="/private/tmp"
        )
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.authority_dir = self.root / "Library/WinsVPN/ReleasePythonAuthority/v2"
        self.receipt_dir = self.root / "Library/WinsVPN/ReleasePython"
        self.runtime = self.receipt_dir / "3.14.7"
        self.repo = self.root / "repo"
        for directory in (
            self.authority_dir,
            self.receipt_dir,
            self.runtime,
            self.repo / "tools",
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o755)
            directory.chmod(0o755)
        self.paths = MODULE.ProvisionPaths(
            authority=self.authority_dir / "authority.json",
            boundary=self.authority_dir / "owner-provision",
            journal=self.authority_dir / "owner-provision.transaction.json",
            journal_next=self.authority_dir / "owner-provision.transaction.next",
            receipt=self.receipt_dir / "3.14.7.receipt.json",
            runtime=self.runtime,
            runtime_python=self.runtime / "python3.14",
        )
        shutil.copyfile(TOOL, self.paths.boundary)
        self.paths.boundary.chmod(0o555)
        self.current_receipt = MODULE.canonical_bytes(
            {"contract": MODULE.RECEIPT_CONTRACT, "schema_version": 1}
        )
        self.paths.receipt.write_bytes(self.current_receipt)
        self.paths.receipt.chmod(0o444)
        self.closure: dict[str, str] = {}
        for index, (key, relative) in enumerate(
            MODULE.MIGRATION_CLOSURE_PATHS.items()
        ):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            data = f"{relative}:{index}\n".encode("ascii")
            path.write_bytes(data)
            path.chmod(0o644)
            self.closure[key] = hashlib.sha256(data).hexdigest()
        self.public = public_key(SEED)
        self.authority = self.make_authority()
        self.paths.authority.write_bytes(MODULE.canonical_bytes(self.authority))
        self.paths.authority.chmod(0o444)
        self.operations = FakeOperations()
        for path in (self.paths.boundary, self.paths.authority, self.paths.receipt):
            self.operations.mark(path, MODULE.SF_IMMUTABLE)
        self.policy = MODULE.CustodyPolicy(
            uid=os.getuid(),
            gid=self.root.stat().st_gid,
            require_immutable=True,
            strict_ancestry=True,
            trusted_root=self.root,
        )
        self.plan_path = self.root / "migration-plan.json"
        self.authorization_path = self.root / "owner-authorization.json"
        self.candidate = self.make_candidate()
        self.plan = self.make_plan()
        self.plan_path.write_bytes(MODULE.canonical_bytes(self.plan))
        self.plan_path.chmod(0o600)
        self.authorization = self.make_authorization()
        self.authorization_path.write_bytes(MODULE.canonical_bytes(self.authorization))
        self.authorization_path.chmod(0o600)
        self.reauth_calls: list[Path] = []

    def close(self) -> None:
        self.temporary.cleanup()

    def make_authority(self) -> dict[str, object]:
        return {
            "active_receipt_sha256": hashlib.sha256(self.current_receipt).hexdigest(),
            "active_sequence": 7,
            "authorized_repo_root": str(self.repo),
            "authority_id": "71" * 32,
            "closure": dict(self.closure),
            "contract": MODULE.AUTHORITY_CONTRACT,
            "key_id": self.public.hex(),
            "expires_utc": "2026-08-28T00:00:00Z",
            "not_before_utc": "2026-08-27T00:00:00Z",
            "owner_provision_boundary": str(MODULE.OWNER_PROVISION_PATH),
            "owner_provision_boundary_sha256": hashlib.sha256(
                self.paths.boundary.read_bytes()
            ).hexdigest(),
            "owner_provision_launcher": str(MODULE.OWNER_LAUNCHER_PATH),
            "owner_provision_launcher_build_sha256": "81" * 32,
            "owner_provision_launcher_compiler_sha256": "84" * 32,
            "owner_provision_launcher_device": 123,
            "owner_provision_launcher_inode": 456,
            "owner_provision_launcher_linker_sha256": "85" * 32,
            "owner_provision_launcher_sha256": "82" * 32,
            "owner_provision_launcher_sdk_closure_sha256": "86" * 32,
            "owner_provision_launcher_source_sha256": "83" * 32,
            "runtime_launcher_sha256": "c4" * 32,
            "runtime_python_sha256": "c1" * 32,
            "schema_version": 3,
            "signing_policy": {
                "authority_chain": ["PSF"],
                "gatekeeper_origin": "PSF",
                "gatekeeper_source": "Developer ID",
                "requirements": {"python3": "designated"},
                "team_identifier": "BMM5U3QVKW",
            },
            "signature_algorithm": MODULE.AUTHORITY_ALGORITHM,
        }

    def make_candidate(self) -> bytes:
        return MODULE.canonical_bytes(
            {
                "authenticated": True,
                "contract": MODULE.RECEIPT_CONTRACT,
                "controller_sha256": self.closure["wrapper_sha256"],
                "custody_closure": dict(self.closure),
                "executable_path": str(MODULE.RUNTIME_PYTHON),
                "executable_sha256": "c1" * 32,
                "launcher_primary_sha256": "c4" * 32,
                "owner_provision_launcher": str(MODULE.OWNER_LAUNCHER_PATH),
                "owner_provision_launcher_build_sha256": self.authority[
                    "owner_provision_launcher_build_sha256"
                ],
                "owner_provision_launcher_compiler_sha256": self.authority[
                    "owner_provision_launcher_compiler_sha256"
                ],
                "owner_provision_launcher_device": self.authority[
                    "owner_provision_launcher_device"
                ],
                "owner_provision_launcher_inode": self.authority[
                    "owner_provision_launcher_inode"
                ],
                "owner_provision_launcher_linker_sha256": self.authority[
                    "owner_provision_launcher_linker_sha256"
                ],
                "owner_provision_launcher_sha256": self.authority[
                    "owner_provision_launcher_sha256"
                ],
                "owner_provision_launcher_sdk_closure_sha256": self.authority[
                    "owner_provision_launcher_sdk_closure_sha256"
                ],
                "owner_provision_launcher_source_sha256": self.authority[
                    "owner_provision_launcher_source_sha256"
                ],
                "package_sha256": "c2" * 32,
                "package_signature_status": "Status: signed fixture",
                "provisioner_sha256": self.closure["provisioner_sha256"],
                "receipt_schema_sha256": self.closure[
                    "custody_controller_sha256"
                ],
                "runtime_path": str(MODULE.RUNTIME_PATH),
                "schema_version": 3,
                "wheel_count": 1,
                "wheels": [
                    {"name": "fixture.whl", "sha256": "c3" * 32}
                ],
            }
        )

    def make_plan(self) -> dict[str, object]:
        candidate_digest = hashlib.sha256(self.candidate).hexdigest()
        current_digest = hashlib.sha256(self.current_receipt).hexdigest()
        created = "2026-08-27T12:00:00Z"
        expires = "2026-08-27T13:00:00Z"
        migration_id = MODULE._migration_id(
            current_receipt_sha256=current_digest,
            candidate_receipt_sha256=candidate_digest,
            closure=self.closure,
            authority=self.authority,
            created_utc=created,
            expires_utc=expires,
        )
        return {
            "authority": copy.deepcopy(self.authority),
            "candidate_receipt_ascii": self.candidate.decode("ascii"),
            "candidate_receipt_sha256": candidate_digest,
            "closure": dict(self.closure),
            "contract": MODULE.PLAN_CONTRACT,
            "created_utc": created,
            "current_receipt_sha256": current_digest,
            "expected_external_authority_operation": {
                "action": "owner-authority-approve-and-atomically-publish-receipt",
                "authority_id": self.authority["authority_id"],
                "authority_key_id": self.authority["key_id"],
                "authority_path": str(MODULE.AUTHORITY_PATH),
                "candidate_receipt_sha256": candidate_digest,
                "current_receipt_sha256": current_digest,
                "expected_active_sequence": 7,
                "migration_id": migration_id,
                "next_sequence": 8,
                "receipt_path": str(MODULE.RECEIPT_PATH),
            },
            "expires_utc": expires,
            "migration_id": migration_id,
            "schema_version": 2,
            "status": "OWNER-BLOCKED: Python runtime receipt migration requires a current external owner-authority approval",
        }

    def make_authorization(
        self,
        *,
        seed: bytes = SEED,
        overrides: dict[str, object] | None = None,
    ) -> dict[str, object]:
        signed: dict[str, object] = {
            "authority_id": self.authority["authority_id"],
            "authorization_id": "91" * 32,
            "authorization_path": str(self.authorization_path),
            "authorized_repo_root": str(self.repo),
            "candidate_receipt_sha256": self.plan["candidate_receipt_sha256"],
            "closure": dict(self.closure),
            "contract": MODULE.AUTHORIZATION_CONTRACT,
            "current_receipt_sha256": self.plan["current_receipt_sha256"],
            "expires_utc": "2026-08-27T12:10:00Z",
            "issued_utc": "2026-08-27T12:00:00Z",
            "migration_id": self.plan["migration_id"],
            "nonce": "92" * 32,
            "not_before_utc": "2026-08-27T12:00:00Z",
            "owner_provision_boundary_sha256": self.authority[
                "owner_provision_boundary_sha256"
            ],
            "owner_provision_launcher_sha256": self.authority[
                "owner_provision_launcher_sha256"
            ],
            "owner_provision_launcher_compiler_sha256": self.authority[
                "owner_provision_launcher_compiler_sha256"
            ],
            "owner_provision_launcher_linker_sha256": self.authority[
                "owner_provision_launcher_linker_sha256"
            ],
            "owner_provision_launcher_sdk_closure_sha256": self.authority[
                "owner_provision_launcher_sdk_closure_sha256"
            ],
            "plan_sha256": hashlib.sha256(
                MODULE.canonical_bytes(self.plan)
            ).hexdigest(),
            "receipt_path": str(MODULE.RECEIPT_PATH),
            "schema_version": 2,
            "sequence": 7,
        }
        signed.update(overrides or {})
        signature = sign(seed, MODULE.DOMAIN + MODULE.canonical_bytes(signed))
        return {
            "algorithm": MODULE.ALGORITHM,
            "authorization": signed,
            "contract": MODULE.AUTHORIZATION_ENVELOPE_CONTRACT,
            "key_id": self.authority["key_id"],
            "schema_version": 2,
            "signature": signature.hex(),
        }

    def write_authorization(self, authorization: dict[str, object]) -> None:
        self.authorization = authorization
        self.authorization_path.write_bytes(MODULE.canonical_bytes(authorization))

    def write_authority(self, authority: dict[str, object]) -> None:
        self.paths.authority.chmod(0o644)
        self.paths.authority.write_bytes(MODULE.canonical_bytes(authority))
        self.paths.authority.chmod(0o444)
        self.operations.mark(self.paths.authority, MODULE.SF_IMMUTABLE)

    def reauthenticate(
        self,
        path: Path,
        candidate: bytes,
        closure: dict[str, str],
        _dependencies: MODULE.HeldDependencies | None,
        owner_uid: int,
        owner_gid: int,
    ) -> None:
        self.assert_equal(owner_uid, os.getuid())
        self.assert_equal(owner_gid, pwd.getpwuid(os.getuid()).pw_gid)
        self.assert_candidate(path, candidate, closure)
        self.reauth_calls.append(path)

    def assert_candidate(
        self, path: Path, candidate: bytes, closure: dict[str, str]
    ) -> None:
        self.assert_bytes(path.read_bytes(), candidate)
        self.assert_bytes(candidate, self.candidate)
        self.assert_equal(closure, self.closure)

    @staticmethod
    def assert_bytes(left: bytes, right: bytes) -> None:
        if left != right:
            raise AssertionError("candidate bytes drifted")

    @staticmethod
    def assert_equal(left: object, right: object) -> None:
        if left != right:
            raise AssertionError("candidate closure drifted")

    def apply(
        self,
        *,
        reauthenticate=None,
        crash_hook=MODULE._noop_crash_hook,
        dependency_custody=None,
    ) -> dict[str, object]:
        return MODULE.apply_transaction(
            self.plan_path,
            self.authorization_path,
            paths=self.paths,
            policy=self.policy,
            operations=self.operations,
            now=NOW,
            reauthenticate=reauthenticate or self.reauthenticate,
            crash_hook=crash_hook,
            dependency_custody=dependency_custody,
        )

    def recover(
        self,
        *,
        reauthenticate=None,
        dependency_custody=None,
        crash_hook=MODULE._noop_crash_hook,
        now=NOW,
    ) -> dict[str, object]:
        return MODULE.recover_transaction(
            paths=self.paths,
            policy=self.policy,
            operations=self.operations,
            reauthenticate=reauthenticate or self.reauthenticate,
            dependency_custody=dependency_custody,
            crash_hook=crash_hook,
            now=now,
        )


class InitialAuthorityPublicationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.fixture.paths.authority.unlink()
        current_receipt = MODULE._json(
            self.fixture.candidate,
            "initial authority receipt fixture",
            maximum=MODULE.MAX_RECEIPT,
        )
        current_receipt["custody_closure"] = {
            key: "b1" * 32 for key in self.fixture.closure
        }
        current_receipt["launcher_tree_sha256"] = "b2" * 32
        current_receipt["launcher_identity_sha256"] = "b3" * 32
        current_receipt["launcher_dir_identity"] = "initial-fixture-launcher"
        self.fixture.current_receipt = MODULE.canonical_bytes(current_receipt)
        self.fixture.paths.receipt.chmod(0o644)
        self.fixture.paths.receipt.write_bytes(self.fixture.current_receipt)
        self.fixture.paths.receipt.chmod(0o444)
        authority = self.fixture.make_authority()
        authority["active_sequence"] = 1
        authority["authority_id"] = "73" * 32
        authority["key_id"] = self.fixture.public.hex()
        self.authority = authority
        self.authority_source = self.fixture.root / "initial-authority.json"
        self.envelope_path = self.fixture.root / "initial-authority-envelope.json"
        self.authority_source.write_bytes(MODULE.canonical_bytes(authority))
        self.authority_source.chmod(0o600)
        self.capability = FakeNativeCapability(
            str(authority["runtime_launcher_sha256"]),
            str(authority["runtime_python_sha256"]),
        )
        self.capability.record.update(
            {
                "controller_sha256": authority["owner_provision_boundary_sha256"],
                "launcher_build_sha256": authority[
                    "owner_provision_launcher_build_sha256"
                ],
                "launcher_compiler_sha256": authority[
                    "owner_provision_launcher_compiler_sha256"
                ],
                "launcher_device": authority["owner_provision_launcher_device"],
                "launcher_inode": authority["owner_provision_launcher_inode"],
                "launcher_linker_sha256": authority[
                    "owner_provision_launcher_linker_sha256"
                ],
                "launcher_sdk_closure_sha256": authority[
                    "owner_provision_launcher_sdk_closure_sha256"
                ],
                "launcher_sha256": authority["owner_provision_launcher_sha256"],
                "launcher_source_sha256": authority[
                    "owner_provision_launcher_source_sha256"
                ],
            }
        )
        signed = {
            "action": "publish-create-only-v2-authority",
            "active_receipt_sha256": hashlib.sha256(
                self.fixture.current_receipt
            ).hexdigest(),
            "authority_path": str(MODULE.AUTHORITY_PATH),
            "authority_sha256": hashlib.sha256(
                self.authority_source.read_bytes()
            ).hexdigest(),
            "contract": MODULE.INITIAL_AUTHORITY_AUTHORIZATION_CONTRACT,
            "expires_utc": "2026-08-27T12:10:00Z",
            "issued_utc": "2026-08-27T12:00:00Z",
            "nonce": "74" * 32,
            "not_before_utc": "2026-08-27T12:00:00Z",
            "owner_provision_boundary_sha256": self.capability.record[
                "controller_sha256"
            ],
            "owner_provision_launcher_device": self.capability.record[
                "launcher_device"
            ],
            "owner_provision_launcher_inode": self.capability.record[
                "launcher_inode"
            ],
            "owner_provision_launcher_sha256": self.capability.record[
                "launcher_sha256"
            ],
            "schema_version": 1,
        }
        signature = sign(
            SEED, MODULE.INITIAL_AUTHORITY_DOMAIN + MODULE.canonical_bytes(signed)
        )
        self.envelope = {
            "algorithm": MODULE.ALGORITHM,
            "authorization": signed,
            "contract": MODULE.INITIAL_AUTHORITY_ENVELOPE_CONTRACT,
            "key_id": self.fixture.public.hex(),
            "schema_version": 1,
            "signature": signature.hex(),
        }
        self.envelope_path.write_bytes(MODULE.canonical_bytes(self.envelope))
        self.envelope_path.chmod(0o600)

    def tearDown(self) -> None:
        self.fixture.close()

    def publish(
        self,
        crash_hook=MODULE._noop_crash_hook,
        *,
        now: datetime = NOW,
    ) -> dict[str, object]:
        with mock.patch.object(
            MODULE, "INITIAL_AUTHORITY_KEY_ID", self.fixture.public.hex()
        ):
            return MODULE.publish_initial_authority(
                self.authority_source,
                self.envelope_path,
                paths=self.fixture.paths,
                policy=self.fixture.policy,
                operations=self.fixture.operations,
                now=now,
                capability=self.capability,
                crash_hook=crash_hook,
            )

    def test_signed_create_only_publication_seals_exact_authority(self) -> None:
        result = self.publish()
        self.assertEqual(result["result"], "initial-authority-published-and-sealed")
        self.assertEqual(
            self.fixture.paths.authority.read_bytes(), self.authority_source.read_bytes()
        )
        descriptor = os.open(self.fixture.paths.authority, os.O_RDONLY)
        try:
            self.assertEqual(stat.S_IMODE(os.fstat(descriptor).st_mode), 0o444)
            self.assertEqual(
                self.fixture.operations.flags_fd(descriptor), MODULE.SF_IMMUTABLE
            )
        finally:
            os.close(descriptor)
        self.assertFalse(
            (self.fixture.authority_dir / MODULE.INITIAL_AUTHORITY_JOURNAL_NAME).exists()
        )

    def test_every_publication_crash_point_recovers_with_same_signed_inputs(self) -> None:
        for point in (
            "initial-authority-intent",
            "initial-authority-staged",
            "initial-authority-renamed",
            "initial-authority-published",
        ):
            with self.subTest(point=point):
                self.tearDown()
                self.setUp()

                def crash(actual: str) -> None:
                    if actual == point:
                        raise MODULE.SimulatedProcessCrash(actual)

                with self.assertRaises(MODULE.SimulatedProcessCrash):
                    self.publish(crash)
                self.publish()

    def test_wrong_signature_and_preexisting_target_fail_closed(self) -> None:
        bad = copy.deepcopy(self.envelope)
        bad["signature"] = "00" * 64
        self.envelope_path.write_bytes(MODULE.canonical_bytes(bad))
        with self.assertRaisesRegex(MODULE.ProvisionError, "signature"):
            self.publish()
        self.envelope_path.write_bytes(MODULE.canonical_bytes(self.envelope))
        self.fixture.paths.authority.write_bytes(self.authority_source.read_bytes())
        self.fixture.paths.authority.chmod(0o444)
        self.fixture.operations.mark(
            self.fixture.paths.authority, MODULE.SF_IMMUTABLE
        )
        with self.assertRaisesRegex(MODULE.ProvisionError, "already exists"):
            self.publish()

    def test_expired_envelope_can_be_replaced_for_the_same_authority(self) -> None:
        def crash_after_rename(point: str) -> None:
            if point == "initial-authority-renamed":
                raise MODULE.SimulatedProcessCrash(point)

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.publish(crash_after_rename)
        resumed_at = NOW + timedelta(days=1)
        with self.assertRaisesRegex(MODULE.ProvisionError, "expired"):
            self.publish(now=resumed_at)
        signed = copy.deepcopy(self.envelope["authorization"])
        signed["issued_utc"] = "2026-08-28T12:00:00Z"
        signed["not_before_utc"] = "2026-08-28T12:00:00Z"
        signed["expires_utc"] = "2026-08-28T12:10:00Z"
        signed["nonce"] = "75" * 32
        refreshed = {
            **self.envelope,
            "authorization": signed,
            "signature": sign(
                SEED,
                MODULE.INITIAL_AUTHORITY_DOMAIN + MODULE.canonical_bytes(signed),
            ).hex(),
        }
        self.envelope_path.write_bytes(MODULE.canonical_bytes(refreshed))
        result = self.publish(now=resumed_at)
        self.assertEqual(result["result"], "initial-authority-published-and-sealed")

    def test_next_journal_is_promoted_only_as_exact_successor(self) -> None:
        digest = hashlib.sha256(self.authority_source.read_bytes()).hexdigest()
        envelope_digest = hashlib.sha256(self.envelope_path.read_bytes()).hexdigest()
        transaction_id = hashlib.sha256(
            MODULE.INITIAL_AUTHORITY_DOMAIN
            + bytes.fromhex(digest)
        ).hexdigest()
        base = {
            "authority_sha256": digest,
            "contract": MODULE.INITIAL_AUTHORITY_JOURNAL_CONTRACT,
            "created_utc": "2026-08-27T12:00:00Z",
            "envelope_sha256": envelope_digest,
            "generation": 1,
            "phase": "preparing",
            "schema_version": 1,
            "stage_name": f"authority.json.initial-publish.{transaction_id}.new",
            "transaction_id": transaction_id,
        }
        current = self.fixture.authority_dir / MODULE.INITIAL_AUTHORITY_JOURNAL_NAME
        next_path = (
            self.fixture.authority_dir / MODULE.INITIAL_AUTHORITY_JOURNAL_NEXT_NAME
        )
        current.write_bytes(MODULE.canonical_bytes(base))
        current.chmod(0o600)
        successor = {**base, "generation": 2, "phase": "staged"}
        next_path.write_bytes(MODULE.canonical_bytes(successor))
        next_path.chmod(0o600)
        held = MODULE.HeldDirectory.open(
            self.fixture.authority_dir, self.fixture.policy
        )
        try:
            selected = MODULE._reconcile_initial_authority_journals(
                held,
                policy=self.fixture.policy,
                operations=self.fixture.operations,
            )
        finally:
            held.close()
        self.assertEqual(selected, MODULE.canonical_bytes(successor))
        self.assertFalse(next_path.exists())
        hostile = {**successor, "generation": 4}
        next_path.write_bytes(MODULE.canonical_bytes(hostile))
        next_path.chmod(0o600)
        held = MODULE.HeldDirectory.open(
            self.fixture.authority_dir, self.fixture.policy
        )
        try:
            with self.assertRaisesRegex(MODULE.ProvisionError, "generation"):
                MODULE._reconcile_initial_authority_journals(
                    held,
                    policy=self.fixture.policy,
                    operations=self.fixture.operations,
                )
        finally:
            held.close()


class OwnerProvisionTransactionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def assert_production_recovery_authenticates(
        self,
        *,
        fixture: Fixture | None = None,
        ordinary_entry_reaches_receipt: bool = False,
    ) -> None:
        selected_fixture = fixture or self.fixture
        class ProductionReceiptReached(Exception):
            pass

        original_open = MODULE.HeldFile.open

        def open_production_path(path, **kwargs):
            selected = (
                selected_fixture.paths.boundary
                if Path(path) == MODULE.OWNER_PROVISION_PATH
                else path
            )
            return original_open(selected, **kwargs)

        with (
            mock.patch.object(MODULE, "AUTHORITY_PATH", selected_fixture.paths.authority),
            mock.patch.object(MODULE, "PRODUCTION_PATHS", selected_fixture.paths),
            mock.patch.object(MODULE, "SYSTEM_OPERATIONS", selected_fixture.operations),
            mock.patch.object(
                MODULE.CustodyPolicy,
                "production",
                return_value=selected_fixture.policy,
            ),
            mock.patch.object(MODULE.HeldFile, "open", side_effect=open_production_path),
            mock.patch.object(MODULE, "_require_native_bootstrap"),
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(
                MODULE,
                "_validate_active_runtime_receipt",
                side_effect=ProductionReceiptReached,
            ),
        ):
            if ordinary_entry_reaches_receipt:
                with self.assertRaises(ProductionReceiptReached):
                    MODULE._require_production_invocation(
                        allow_interrupted_recovery=False
                    )
            else:
                with self.assertRaises(MODULE.ProvisionError):
                    MODULE._require_production_invocation(
                        allow_interrupted_recovery=False
                    )
            with self.assertRaises(ProductionReceiptReached):
                MODULE._require_production_invocation(
                    allow_interrupted_recovery=True
                )

    def test_happy_path_publishes_both_files_and_consumes_sequence(self) -> None:
        result = self.fixture.apply()
        self.assertEqual(result["result"], "published-and-reauthenticated")
        self.assertEqual(result["sequence"], 8)
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.candidate)
        authority = MODULE._parse_authority(self.fixture.paths.authority.read_bytes())
        self.assertEqual(authority["active_sequence"], 8)
        self.assertEqual(
            authority["active_receipt_sha256"],
            hashlib.sha256(self.fixture.candidate).hexdigest(),
        )
        self.assertEqual(len(self.fixture.reauth_calls), 2)
        self.assertFalse(self.fixture.paths.journal.exists())

    def test_replay_and_stale_plan_are_rejected(self) -> None:
        self.fixture.apply()
        with self.assertRaisesRegex(MODULE.ProvisionError, "stale|authority"):
            self.fixture.apply()

    def test_recovery_rejects_reserved_leaf_aliases_before_cleanup(self) -> None:
        cases = (
            ("authority_stage_name", "owner-launcher"),
            ("authority_backup_name", self.fixture.paths.authority.name),
            ("receipt_stage_name", self.fixture.paths.receipt.name),
            ("authority_stage_name", self.fixture.paths.runtime.name),
        )
        for key, alias in cases:
            with self.subTest(key=key, alias=alias):
                fixture = Fixture()
                try:
                    sibling = fixture.authority_dir / "owner-launcher"
                    sibling.write_bytes(b"immutable sibling\n")
                    sibling.chmod(0o444)
                    fixture.operations.mark(sibling, MODULE.SF_IMMUTABLE)

                    def crash(point: str) -> None:
                        if point == "journal-created":
                            raise MODULE.SimulatedProcessCrash()

                    with self.assertRaises(MODULE.SimulatedProcessCrash):
                        fixture.apply(crash_hook=crash)
                    journal = MODULE._parse_journal(
                        fixture.paths.journal.read_bytes()
                    )
                    journal[key] = alias
                    fixture.paths.journal.write_bytes(
                        MODULE.canonical_bytes(journal)
                    )
                    with self.assertRaisesRegex(
                        MODULE.ProvisionError,
                        "transaction-bound|reserved leaf|pairwise distinct",
                    ):
                        fixture.recover()
                    self.assertEqual(
                        fixture.paths.authority.read_bytes(),
                        MODULE.canonical_bytes(fixture.authority),
                    )
                    self.assertEqual(
                        fixture.paths.receipt.read_bytes(), fixture.current_receipt
                    )
                    self.assertEqual(sibling.read_bytes(), b"immutable sibling\n")
                    sibling_fd = os.open(sibling, os.O_RDONLY)
                    try:
                        self.assertEqual(
                            fixture.operations.flags_fd(sibling_fd),
                            MODULE.SF_IMMUTABLE,
                        )
                    finally:
                        os.close(sibling_fd)
                finally:
                    fixture.close()

    def test_journal_names_are_pairwise_distinct_and_not_cross_transaction(self) -> None:
        def crash(point: str) -> None:
            if point == "journal-created":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)
        original = MODULE._parse_journal(self.fixture.paths.journal.read_bytes())

        duplicate = dict(original)
        duplicate["authority_stage_name"] = duplicate["authority_backup_name"]
        with self.assertRaisesRegex(MODULE.ProvisionError, "pairwise distinct"):
            MODULE._parse_journal(MODULE.canonical_bytes(duplicate))

        replay = dict(original)
        replay["transaction_id"] = "ab" * 32
        self.fixture.paths.journal.write_bytes(MODULE.canonical_bytes(replay))
        with self.assertRaisesRegex(MODULE.ProvisionError, "transaction-bound"):
            self.fixture.recover()

    def test_imported_api_global_rebind_cannot_declassify_production_paths(self) -> None:
        fixed = MODULE.ProvisionPaths.production()
        rebound = {
            "AUTHORITY_PATH": self.fixture.paths.authority,
            "OWNER_PROVISION_PATH": self.fixture.paths.boundary,
            "OWNER_LAUNCHER_PATH": self.fixture.authority_dir / "owner-launcher",
            "JOURNAL_PATH": self.fixture.paths.journal,
            "JOURNAL_NEXT_PATH": self.fixture.paths.journal_next,
            "RECEIPT_PATH": self.fixture.paths.receipt,
            "RUNTIME_PATH": self.fixture.paths.runtime,
            "RUNTIME_PYTHON": self.fixture.paths.runtime_python,
            "RUNTIME_LAUNCHER": self.fixture.paths.runtime / "launcher/python3.14",
            "RUNTIME_LAUNCHER_ALIAS": self.fixture.paths.runtime / "launcher/python3",
            "PRODUCTION_PATHS": self.fixture.paths,
        }
        with mock.patch.multiple(MODULE, **rebound):
            self.assertEqual(MODULE.ProvisionPaths.production(), fixed)
            self.assertTrue(MODULE._production_paths_requested(fixed))
            with self.assertRaisesRegex(
                MODULE.ProvisionError,
                "exact held ReleasePython invocation closure",
            ):
                MODULE.apply_transaction(
                    self.fixture.plan_path,
                    self.fixture.authorization_path,
                )
            with self.assertRaisesRegex(
                MODULE.ProvisionError,
                "exact held ReleasePython invocation closure",
            ):
                MODULE.recover_transaction()

            with self.assertRaisesRegex(
                MODULE.ProvisionError, "refuses injected transaction dependencies"
            ):
                MODULE.apply_transaction(
                    self.fixture.plan_path,
                    self.fixture.authorization_path,
                    policy=self.fixture.policy,
                    operations=self.fixture.operations,
                    reauthenticate=self.fixture.reauthenticate,
                )

    def test_wrong_signing_key_is_rejected_without_state_change(self) -> None:
        self.fixture.write_authorization(
            self.fixture.make_authorization(seed=OTHER_SEED)
        )
        with self.assertRaisesRegex(MODULE.ProvisionError, "wrong key"):
            self.fixture.apply()
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.current_receipt)

    def test_wrong_authorization_path_is_rejected(self) -> None:
        authorization = self.fixture.make_authorization(
            overrides={"authorization_path": "/private/tmp/wrong.json"}
        )
        self.fixture.write_authorization(authorization)
        with self.assertRaisesRegex(MODULE.ProvisionError, "authorization_path"):
            self.fixture.apply()

    def test_wrong_candidate_hash_is_rejected(self) -> None:
        authorization = self.fixture.make_authorization(
            overrides={"candidate_receipt_sha256": "ab" * 32}
        )
        self.fixture.write_authorization(authorization)
        with self.assertRaisesRegex(MODULE.ProvisionError, "candidate_receipt_sha256"):
            self.fixture.apply()

    def test_wrong_sequence_is_rejected(self) -> None:
        authorization = self.fixture.make_authorization(overrides={"sequence": 8})
        self.fixture.write_authorization(authorization)
        with self.assertRaisesRegex(MODULE.ProvisionError, "sequence"):
            self.fixture.apply()

    def test_expired_future_and_overlong_authorizations_are_rejected(self) -> None:
        cases = (
            {"expires_utc": "2026-08-27T12:00:00Z"},
            {
                "issued_utc": "2026-08-27T12:01:00Z",
                "not_before_utc": "2026-08-27T12:01:00Z",
            },
            {"expires_utc": "2026-08-27T12:20:00Z"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                authorization = self.fixture.make_authorization(overrides=overrides)
                self.fixture.write_authorization(authorization)
                with self.assertRaisesRegex(
                    MODULE.ProvisionError, "expired, future, or overlong"
                ):
                    self.fixture.apply()

    def test_duplicate_and_nonfinite_authorization_json_are_rejected(self) -> None:
        self.fixture.authorization_path.write_bytes(
            b'{"algorithm":"ed25519","algorithm":"ed25519"}\n'
        )
        with self.assertRaisesRegex(MODULE.ProvisionError, "duplicate JSON"):
            self.fixture.apply()
        self.fixture.authorization_path.write_bytes(
            b'{"algorithm":NaN}\n'
        )
        with self.assertRaisesRegex(MODULE.ProvisionError, "non-finite"):
            self.fixture.apply()

    def test_boundary_hash_drift_is_rejected(self) -> None:
        authority = copy.deepcopy(self.fixture.authority)
        authority["owner_provision_boundary_sha256"] = "aa" * 32
        self.fixture.write_authority(authority)
        with self.assertRaisesRegex(MODULE.ProvisionError, "boundary"):
            self.fixture.apply()

    def test_symlink_and_hardlink_authority_are_rejected(self) -> None:
        original = self.fixture.paths.authority
        saved = self.fixture.authority_dir / "saved-authority"
        original.rename(saved)
        original.symlink_to(saved)
        with self.assertRaises(MODULE.ProvisionError):
            self.fixture.apply()
        original.unlink()
        os.link(saved, original)
        self.fixture.operations.mark(original, MODULE.SF_IMMUTABLE)
        with self.assertRaisesRegex(MODULE.ProvisionError, "custody"):
            self.fixture.apply()

    def test_hardlinked_receipt_is_rejected(self) -> None:
        os.link(self.fixture.paths.receipt, self.fixture.receipt_dir / "receipt-link")
        with self.assertRaisesRegex(MODULE.ProvisionError, "custody"):
            self.fixture.apply()

    def test_writable_authority_ancestry_is_rejected(self) -> None:
        self.fixture.authority_dir.chmod(0o777)
        with self.assertRaisesRegex(MODULE.ProvisionError, "ancestor custody"):
            self.fixture.apply()

    def test_missing_system_immutable_flag_is_rejected(self) -> None:
        self.fixture.operations.mark(self.fixture.paths.authority, 0)
        with self.assertRaisesRegex(MODULE.ProvisionError, "system immutable"):
            self.fixture.apply()

    def test_concurrent_authority_transaction_is_rejected(self) -> None:
        held = MODULE.HeldDirectory.open(
            self.fixture.paths.authority.parent, self.fixture.policy
        )
        try:
            fcntl.flock(held.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(MODULE.ProvisionError, "authority lock"):
                self.fixture.apply()
        finally:
            held.close()

    def test_plan_replacement_after_journal_is_rejected_and_rolled_back(self) -> None:
        def replace(point: str) -> None:
            if point == "journal-prepared":
                replacement = self.fixture.root / "replacement-plan"
                replacement.write_bytes(self.fixture.plan_path.read_bytes())
                os.replace(replacement, self.fixture.plan_path)

        with self.assertRaisesRegex(MODULE.ProvisionError, "identity changed|pathname changed"):
            self.fixture.apply(crash_hook=replace)
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.current_receipt)
        self.assertFalse(self.fixture.paths.journal.exists())

    def test_closure_mutation_after_journal_is_rejected_and_rolled_back(self) -> None:
        target = self.fixture.repo / next(iter(MODULE.MIGRATION_CLOSURE_PATHS.values()))

        def mutate(point: str) -> None:
            if point == "journal-prepared":
                target.write_bytes(target.read_bytes() + b"drift")

        with self.assertRaisesRegex(MODULE.ProvisionError, "closure|retained"):
            self.fixture.apply(crash_hook=mutate)
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.current_receipt)

    def test_preflight_runtime_failure_changes_no_authority_or_receipt(self) -> None:
        def refuse(
            _path: Path,
            _candidate: bytes,
            _closure: dict[str, str],
            _dependencies: MODULE.HeldDependencies | None,
            _owner_uid: int,
            _owner_gid: int,
        ) -> None:
            raise MODULE.ProvisionError("strict runtime signature absent")

        with self.assertRaisesRegex(MODULE.ProvisionError, "strict runtime"):
            self.fixture.apply(reauthenticate=refuse)
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.current_receipt)
        self.assertEqual(
            self.fixture.paths.authority.read_bytes(),
            MODULE.canonical_bytes(self.fixture.authority),
        )
        self.assertFalse(self.fixture.paths.journal.exists())

    def test_post_publication_failure_rolls_back_exact_bytes(self) -> None:
        calls = 0

        def second_fails(
            path: Path,
            candidate: bytes,
            closure: dict[str, str],
            _dependencies: MODULE.HeldDependencies | None,
            _owner_uid: int,
            _owner_gid: int,
        ) -> None:
            nonlocal calls
            calls += 1
            self.fixture.assert_candidate(path, candidate, closure)
            if calls == 2:
                raise MODULE.ProvisionError("post publication failed")

        with self.assertRaisesRegex(MODULE.ProvisionError, "post publication"):
            self.fixture.apply(reauthenticate=second_fails)
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.current_receipt)
        self.assertEqual(
            self.fixture.paths.authority.read_bytes(),
            MODULE.canonical_bytes(self.fixture.authority),
        )
        self.assertFalse(self.fixture.paths.journal.exists())

    def test_crash_before_publication_recovers_by_exact_rollback(self) -> None:
        def crash(point: str) -> None:
            if point == "journal-prepared":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)
        result = self.fixture.recover()
        self.assertEqual(result["result"], "rolled-back-before-publication")
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.current_receipt)

    def test_every_partial_staging_crash_is_journaled_and_recoverable(self) -> None:
        points = (
            "journal-created",
            "receipt-stage-created",
            "receipt-backup-created",
            "authority-stage-created",
            "authority-backup-created",
        )
        for expected_point in points:
            with self.subTest(point=expected_point):
                fixture = Fixture()
                try:
                    def crash(point: str) -> None:
                        if point == expected_point:
                            raise MODULE.SimulatedProcessCrash()

                    with self.assertRaises(MODULE.SimulatedProcessCrash):
                        fixture.apply(crash_hook=crash)
                    result = fixture.recover()
                    self.assertEqual(result["result"], "rolled-back-before-publication")
                    self.assertEqual(
                        fixture.paths.receipt.read_bytes(), fixture.current_receipt
                    )
                    self.assertFalse(fixture.paths.journal.exists())
                    self.assertFalse(fixture.paths.journal_next.exists())
                finally:
                    fixture.close()

    def test_crash_after_immutable_clear_restores_exact_old_custody(self) -> None:
        original = self.fixture.operations.set_flags_fd
        tripped = False

        def crash_after_clear(fd: int, flags: int) -> None:
            nonlocal tripped
            original(fd, flags)
            data = os.pread(fd, MODULE.MAX_RECEIPT, 0)
            if not tripped and flags == 0 and data == self.fixture.current_receipt:
                tripped = True
                raise MODULE.SimulatedProcessCrash()

        self.fixture.operations.set_flags_fd = crash_after_clear
        try:
            with self.assertRaises(MODULE.SimulatedProcessCrash):
                self.fixture.apply()
        finally:
            self.fixture.operations.set_flags_fd = original
        descriptor = os.open(self.fixture.paths.receipt, os.O_RDONLY)
        try:
            self.assertEqual(self.fixture.operations.flags_fd(descriptor), 0)
        finally:
            os.close(descriptor)

        authority = MODULE.HeldFile.open(
            self.fixture.paths.authority,
            maximum=MODULE.MAX_AUTHORITY,
            policy=self.fixture.policy,
            operations=self.fixture.operations,
            mode=0o444,
            immutable=True,
        )
        authenticated_receipt = None
        try:
            authority_record = MODULE._parse_authority(authority.data)
            with self.assertRaisesRegex(MODULE.ProvisionError, "system immutable"):
                MODULE._open_runtime_receipt_for_invocation(
                    authority,
                    authority_record,
                    allow_interrupted_recovery=False,
                    paths=self.fixture.paths,
                    policy=self.fixture.policy,
                    operations=self.fixture.operations,
                )
            journal_bytes = self.fixture.paths.journal.read_bytes()
            hostile_journal = MODULE._parse_journal(journal_bytes)
            hostile_journal["phase"] = "prepared"
            self.fixture.paths.journal.write_bytes(
                MODULE.canonical_bytes(hostile_journal)
            )
            try:
                with self.assertRaisesRegex(
                    MODULE.ProvisionError, "exact interrupted publication phase"
                ):
                    MODULE._open_runtime_receipt_for_invocation(
                        authority,
                        authority_record,
                        allow_interrupted_recovery=True,
                        paths=self.fixture.paths,
                        policy=self.fixture.policy,
                        operations=self.fixture.operations,
                    )
            finally:
                self.fixture.paths.journal.write_bytes(journal_bytes)
            authenticated_receipt = MODULE._open_runtime_receipt_for_invocation(
                authority,
                authority_record,
                allow_interrupted_recovery=True,
                paths=self.fixture.paths,
                policy=self.fixture.policy,
                operations=self.fixture.operations,
            )
            self.assertEqual(authenticated_receipt.data, self.fixture.current_receipt)
            authenticated_receipt.validate()
        finally:
            if authenticated_receipt is not None:
                authenticated_receipt.close()
            authority.close()

        class ProductionReceiptReached(Exception):
            pass

        original_open = MODULE.HeldFile.open

        def open_production_path(path, **kwargs):
            selected = (
                self.fixture.paths.boundary
                if Path(path) == MODULE.OWNER_PROVISION_PATH
                else path
            )
            return original_open(selected, **kwargs)

        with (
            mock.patch.object(MODULE, "AUTHORITY_PATH", self.fixture.paths.authority),
            mock.patch.object(MODULE, "PRODUCTION_PATHS", self.fixture.paths),
            mock.patch.object(MODULE, "SYSTEM_OPERATIONS", self.fixture.operations),
            mock.patch.object(
                MODULE.CustodyPolicy,
                "production",
                return_value=self.fixture.policy,
            ),
            mock.patch.object(MODULE.HeldFile, "open", side_effect=open_production_path),
            mock.patch.object(MODULE, "_require_native_bootstrap"),
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(
                MODULE,
                "_validate_active_runtime_receipt",
                side_effect=ProductionReceiptReached,
            ),
        ):
            with self.assertRaisesRegex(MODULE.ProvisionError, "system immutable"):
                MODULE._require_production_invocation(
                    allow_interrupted_recovery=False
                )
            with self.assertRaises(ProductionReceiptReached):
                MODULE._require_production_invocation(
                    allow_interrupted_recovery=True
                )
        result = self.fixture.recover()
        self.assertEqual(result["result"], "rolled-back-before-publication")
        descriptor = os.open(self.fixture.paths.receipt, os.O_RDONLY)
        try:
            self.assertEqual(
                self.fixture.operations.flags_fd(descriptor), MODULE.SF_IMMUTABLE
            )
            self.assertEqual(
                stat.S_IMODE(os.fstat(descriptor).st_mode), 0o444
            )
        finally:
            os.close(descriptor)

    def test_every_leaf_replacement_crash_has_authenticated_production_recovery(
        self,
    ) -> None:
        cases = (
            ("receipt-clear", "flags", "receipt", "old", 0, False),
            ("receipt-rename", "rename", "receipt", "new", 0, False),
            (
                "receipt-reseal",
                "flags",
                "receipt",
                "new",
                MODULE.SF_IMMUTABLE,
                False,
            ),
            ("authority-clear", "flags", "authority", "old", 0, False),
            ("authority-rename", "rename", "authority", "new", 0, False),
            (
                "authority-reseal",
                "flags",
                "authority",
                "new",
                MODULE.SF_IMMUTABLE,
                True,
            ),
        )
        for label, mechanism, role, generation, wanted_flags, ordinary in cases:
            with self.subTest(crash_point=label):
                fixture = Fixture()
                original_flags = fixture.operations.set_flags_fd
                original_replace = MODULE.os.replace
                old_authority = MODULE.canonical_bytes(fixture.authority)
                new_authority = MODULE.canonical_bytes(
                    MODULE._next_authority(
                        fixture.authority,
                        hashlib.sha256(fixture.candidate).hexdigest(),
                    )
                )
                wanted_data = {
                    ("receipt", "old"): fixture.current_receipt,
                    ("receipt", "new"): fixture.candidate,
                    ("authority", "old"): old_authority,
                    ("authority", "new"): new_authority,
                }[(role, generation)]
                tripped = False

                def crash_on_flags(fd: int, flags: int) -> None:
                    nonlocal tripped
                    original_flags(fd, flags)
                    data = os.pread(fd, MODULE.MAX_AUTHORITY, 0)
                    if (
                        mechanism == "flags"
                        and not tripped
                        and flags == wanted_flags
                        and data == wanted_data
                    ):
                        tripped = True
                        raise MODULE.SimulatedProcessCrash()

                def crash_after_rename(*args, **kwargs):
                    nonlocal tripped
                    result = original_replace(*args, **kwargs)
                    source = os.fspath(args[0])
                    target = os.fspath(args[1])
                    expected_target = os.fspath(getattr(fixture.paths, role).name)
                    if (
                        mechanism == "rename"
                        and not tripped
                        and target == expected_target
                        and source.endswith(".new")
                    ):
                        tripped = True
                        raise MODULE.SimulatedProcessCrash()
                    return result

                fixture.operations.set_flags_fd = crash_on_flags
                try:
                    with mock.patch.object(
                        MODULE.os, "replace", side_effect=crash_after_rename
                    ):
                        with self.assertRaises(MODULE.SimulatedProcessCrash):
                            fixture.apply()
                    self.assertTrue(tripped)
                    self.assert_production_recovery_authenticates(
                        fixture=fixture,
                        ordinary_entry_reaches_receipt=ordinary,
                    )
                finally:
                    fixture.operations.set_flags_fd = original_flags
                    fixture.close()

    def test_crash_after_receipt_rolls_forward_and_reauthenticates(self) -> None:
        def crash(point: str) -> None:
            if point == "receipt-replaced":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.candidate)
        result = self.fixture.recover()
        self.assertEqual(result["result"], "rolled-forward-and-reauthenticated")
        self.assertEqual(
            MODULE._parse_authority(self.fixture.paths.authority.read_bytes())[
                "active_sequence"
            ],
            8,
        )

    def test_crash_after_authority_rolls_forward_and_reauthenticates(self) -> None:
        def crash(point: str) -> None:
            if point == "authority-replaced":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)
        result = self.fixture.recover()
        self.assertEqual(result["result"], "rolled-forward-and-reauthenticated")
        self.assertFalse(self.fixture.paths.journal.exists())

    def test_crash_after_reauthentication_is_idempotently_recovered(self) -> None:
        def crash(point: str) -> None:
            if point == "post-publication-reauthenticated":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)
        result = self.fixture.recover()
        self.assertEqual(result["result"], "rolled-forward-and-reauthenticated")

    def test_journal_free_terminal_recovery_rejects_expired_authority(self) -> None:
        self.fixture.apply()
        authority = MODULE._parse_authority(
            self.fixture.paths.authority.read_bytes()
        )
        authority["not_before_utc"] = "2020-01-01T00:00:00Z"
        authority["expires_utc"] = "2020-01-01T00:30:00Z"
        self.fixture.write_authority(authority)
        with self.assertRaisesRegex(
            MODULE.ProvisionError,
            "journal-free terminal recovery authority is expired",
        ):
            self.fixture.recover(now=NOW)

    def test_journaled_recovery_has_a_narrow_post_expiry_crash_window(self) -> None:
        authority = copy.deepcopy(self.fixture.authority)
        authority["not_before_utc"] = "2026-08-27T11:00:00Z"
        authority["expires_utc"] = "2026-08-27T12:01:00Z"
        journal = {"created_utc": "2026-08-27T12:00:00Z"}
        MODULE._require_journaled_recovery_window(
            authority,
            journal,
            datetime(2026, 8, 27, 12, 10, tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(
            MODULE.ProvisionError, "bounded authority window"
        ):
            MODULE._require_journaled_recovery_window(
                authority,
                journal,
                datetime(2026, 8, 27, 12, 31, tzinfo=timezone.utc),
            )
        journal["created_utc"] = "2026-08-27T12:02:00Z"
        with self.assertRaisesRegex(
            MODULE.ProvisionError, "bounded authority window"
        ):
            MODULE._require_journaled_recovery_window(
                authority,
                journal,
                datetime(2026, 8, 27, 12, 2, tzinfo=timezone.utc),
            )

    def test_every_fixed_target_independently_enforces_production_boundary(self) -> None:
        fixed = MODULE.ProvisionPaths.production()
        names = tuple(MODULE.ProvisionPaths.__dataclass_fields__)

        def paths_with(base, **changes):
            values = {name: getattr(base, name) for name in names}
            values.update(changes)
            return MODULE.ProvisionPaths(**values)

        def require_apply_and_recover_rejection(paths) -> None:
            with self.assertRaisesRegex(
                MODULE.ProvisionError, "production apply requires every fixed path"
            ):
                MODULE.apply_transaction(
                    self.fixture.plan_path,
                    self.fixture.authorization_path,
                    paths=paths,
                )
            with self.assertRaisesRegex(
                MODULE.ProvisionError,
                "production recovery requires every fixed path",
            ):
                MODULE.recover_transaction(paths=paths)

        for name in names:
            with self.subTest(independent_fixed_target=name):
                require_apply_and_recover_rejection(
                    paths_with(
                        self.fixture.paths,
                        **{name: getattr(fixed, name)},
                    )
                )

        for name in ("runtime", "runtime_python"):
            with self.subTest(changed_unused_runtime_field=name):
                require_apply_and_recover_rejection(
                    paths_with(
                        fixed,
                        **{name: getattr(self.fixture.paths, name)},
                    )
                )

    def test_every_cleanup_unlink_and_fsync_crash_is_idempotently_recovered(
        self,
    ) -> None:
        points = tuple(
            point
            for key in (
                "authority_stage_name",
                "receipt_stage_name",
                "authority_backup_name",
                "receipt_backup_name",
            )
            for point in (
                f"cleanup-before-unlink-{key}",
                f"cleanup-after-unlink-{key}",
                f"cleanup-after-fsync-{key}",
            )
        ) + (
            "cleanup-before-unlink-journal-next",
            "cleanup-after-unlink-journal-next",
            "cleanup-after-fsync-journal-next",
            "cleanup-before-unlink-journal",
            "cleanup-after-unlink-journal",
            "cleanup-after-fsync-journal",
        )
        for expected_point in points:
            with self.subTest(point=expected_point):
                fixture = Fixture()
                try:
                    def crash(point: str) -> None:
                        if point == expected_point:
                            raise MODULE.SimulatedProcessCrash()

                    with self.assertRaises(MODULE.SimulatedProcessCrash):
                        fixture.apply(crash_hook=crash)
                    result = fixture.recover()
                    self.assertIn(
                        result["result"],
                        {
                            "rolled-forward-and-reauthenticated",
                            "authenticated-terminal-already-clean",
                        },
                    )
                    self.assertEqual(
                        fixture.paths.receipt.read_bytes(), fixture.candidate
                    )
                    authority = MODULE._parse_authority(
                        fixture.paths.authority.read_bytes()
                    )
                    self.assertEqual(authority["active_sequence"], 8)
                    self.assertFalse(fixture.paths.journal.exists())
                    self.assertFalse(fixture.paths.journal_next.exists())
                    residue = [
                        path.name
                        for directory in (fixture.authority_dir, fixture.receipt_dir)
                        for path in directory.iterdir()
                        if ".owner-provision." in path.name
                    ]
                    self.assertEqual(residue, [])
                finally:
                    fixture.close()

    def test_recovery_rejects_unknown_partial_publication(self) -> None:
        def crash(point: str) -> None:
            if point == "receipt-replaced":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)
        self.fixture.paths.authority.chmod(0o644)
        self.fixture.paths.authority.write_bytes(b"unknown authority\n")
        self.fixture.paths.authority.chmod(0o444)
        self.fixture.operations.mark(self.fixture.paths.authority, MODULE.SF_IMMUTABLE)
        with self.assertRaisesRegex(MODULE.ProvisionError, "unrecognized"):
            self.fixture.recover()

    def test_recovery_failure_rolls_back_both_files(self) -> None:
        def crash(point: str) -> None:
            if point == "authority-replaced":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)

        def fail_reauth(
            _path: Path,
            _candidate: bytes,
            _closure: dict[str, str],
            _dependencies: MODULE.HeldDependencies | None,
            _owner_uid: int,
            _owner_gid: int,
        ) -> None:
            raise MODULE.ProvisionError("recovery runtime invalid")

        with self.assertRaisesRegex(MODULE.ProvisionError, "recovery runtime"):
            self.fixture.recover(reauthenticate=fail_reauth)
        self.assertEqual(self.fixture.paths.receipt.read_bytes(), self.fixture.current_receipt)
        self.assertEqual(
            self.fixture.paths.authority.read_bytes(),
            MODULE.canonical_bytes(self.fixture.authority),
        )

    def test_journal_next_with_higher_generation_is_recovered(self) -> None:
        def crash(point: str) -> None:
            if point == "receipt-replaced":
                raise MODULE.SimulatedProcessCrash()

        with self.assertRaises(MODULE.SimulatedProcessCrash):
            self.fixture.apply(crash_hook=crash)
        journal = MODULE._parse_journal(self.fixture.paths.journal.read_bytes())
        journal["generation"] = int(journal["generation"]) + 1
        journal["phase"] = "receipt-published"
        self.fixture.paths.journal_next.write_bytes(MODULE.canonical_bytes(journal))
        self.fixture.paths.journal_next.chmod(0o600)
        result = self.fixture.recover()
        self.assertEqual(result["result"], "rolled-forward-and-reauthenticated")

    def test_candidate_receipt_must_bind_exact_closure(self) -> None:
        altered = copy.deepcopy(self.fixture.plan)
        candidate = MODULE._json(
            self.fixture.candidate, "candidate", maximum=MODULE.MAX_RECEIPT
        )
        candidate["custody_closure"] = {
            **self.fixture.closure,
            "wrapper_sha256": "aa" * 32,
        }
        data = MODULE.canonical_bytes(candidate)
        altered["candidate_receipt_ascii"] = data.decode("ascii")
        altered["candidate_receipt_sha256"] = hashlib.sha256(data).hexdigest()
        self.fixture.plan_path.write_bytes(MODULE.canonical_bytes(altered))
        with self.assertRaisesRegex(MODULE.ProvisionError, "closure"):
            self.fixture.apply()

    def test_candidate_receipt_must_bind_native_launcher_derivation(self) -> None:
        candidate = MODULE._parse_candidate_receipt(
            self.fixture.candidate, self.fixture.closure
        )
        for key in (
            "owner_provision_launcher_sha256",
            "owner_provision_launcher_source_sha256",
            "owner_provision_launcher_build_sha256",
            "owner_provision_launcher_compiler_sha256",
            "owner_provision_launcher_linker_sha256",
            "owner_provision_launcher_sdk_closure_sha256",
        ):
            with self.subTest(key=key):
                altered = copy.deepcopy(candidate)
                altered[key] = "ab" * 32
                with self.assertRaisesRegex(
                    MODULE.ProvisionError, "native binding"
                ):
                    MODULE._validate_native_receipt_authority(
                        altered, self.fixture.authority
                    )

    def test_exact_legacy_active_receipt_is_migration_compatible(self) -> None:
        legacy = {
            "authenticated": True,
            "contract": "winsvpn-macos-release-python-runtime-v1",
            "executable_path": str(MODULE.RUNTIME_PYTHON),
            "executable_sha256": self.fixture.authority["runtime_python_sha256"],
            "launcher_dir_identity": "1:2:0:0:555:1:2:3",
            "launcher_identity_sha256": "d1" * 32,
            "launcher_tree_sha256": "d2" * 32,
            "runtime_path": str(MODULE.RUNTIME_PATH),
            "schema_version": 1,
        }
        MODULE._validate_active_runtime_receipt(legacy, self.fixture.authority)
        legacy["executable_sha256"] = "ab" * 32
        MODULE._validate_active_runtime_receipt(legacy, self.fixture.authority)

        schema_three = dict(legacy)
        schema_three["contract"] = MODULE.RECEIPT_CONTRACT
        schema_three["schema_version"] = 3
        with self.assertRaisesRegex(MODULE.ProvisionError, "differs from authority"):
            MODULE._validate_active_runtime_receipt(
                schema_three,
                self.fixture.authority,
            )

    def test_authorization_must_bind_native_launcher_derivation(self) -> None:
        for key in (
            "owner_provision_launcher_sha256",
            "owner_provision_launcher_compiler_sha256",
            "owner_provision_launcher_linker_sha256",
            "owner_provision_launcher_sdk_closure_sha256",
        ):
            with self.subTest(key=key):
                fixture = Fixture()
                try:
                    authorization = fixture.make_authorization(
                        overrides={key: "ab" * 32}
                    )
                    fixture.write_authorization(authorization)
                    with self.assertRaisesRegex(MODULE.ProvisionError, key):
                        fixture.apply()
                finally:
                    fixture.close()


@unittest.skipUnless(sys.platform == "darwin", "macOS vnode custody is required")
class OwnerProvisionInterpreterCustodyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wins-release-python-interpreter-", dir="/private/tmp"
        )
        self.root = Path(self.temporary.name)
        self.sealed = self.root / "sealed"
        self.binary_dir = self.sealed / "bin"
        self.launcher_dir = self.sealed / "launcher"
        self.binary_dir.mkdir(parents=True)
        self.launcher_dir.mkdir()
        self.executable = self.binary_dir / "python3.14"
        self.launcher = self.launcher_dir / "python3.14"
        self.launcher_alias = self.launcher_dir / "python3"
        self.controller = self.sealed / "owner-provision"
        self.original = b"reviewed release python executable\n"
        self.launcher_bytes = b"#!/bin/sh\nexec reviewed-python \"$@\"\n"
        self.executable.write_bytes(self.original)
        self.launcher.write_bytes(self.launcher_bytes)
        self.launcher_alias.write_bytes(self.launcher_bytes)
        self.controller.write_bytes(b"reviewed owner provision controller\n")
        self.executable.chmod(0o555)
        self.launcher.chmod(0o555)
        self.launcher_alias.chmod(0o555)
        self.controller.chmod(0o555)
        self.binary_dir.chmod(0o555)
        self.launcher_dir.chmod(0o555)
        self.sealed.chmod(0o555)
        self.operations = FakeOperations()
        for path in (
            self.executable,
            self.launcher,
            self.launcher_alias,
            self.controller,
        ):
            self.operations.mark(path, MODULE.SF_IMMUTABLE)
        self.policy = MODULE.CustodyPolicy(
            uid=os.getuid(),
            gid=self.executable.stat().st_gid,
            require_immutable=True,
            strict_ancestry=True,
            trusted_root=self.sealed,
        )
        held_launchers = {
            path.name: MODULE.HeldFile.open(
                path,
                maximum=MODULE.MAX_RUNTIME_LAUNCHER,
                policy=self.policy,
                operations=self.operations,
                mode=0o555,
                immutable=True,
            )
            for path in (self.launcher_alias, self.launcher)
        }
        try:
            launcher_tree, launcher_identity, launcher_directory = (
                MODULE._launcher_tree_hashes(held_launchers, self.operations)
            )
        finally:
            for held in held_launchers.values():
                held.close()
        self.receipt = MODULE.canonical_bytes(
            {
                "authenticated": True,
                "contract": MODULE.RECEIPT_CONTRACT,
                "executable_path": str(self.executable),
                "executable_sha256": hashlib.sha256(self.original).hexdigest(),
                "launcher_dir_identity": launcher_directory,
                "launcher_identity_sha256": launcher_identity,
                "launcher_primary_sha256": hashlib.sha256(
                    self.launcher_bytes
                ).hexdigest(),
                "launcher_tree_sha256": launcher_tree,
                "runtime_path": str(MODULE.RUNTIME_PATH),
                "schema_version": 3,
            }
        )

    def tearDown(self) -> None:
        for path in (self.binary_dir, self.launcher_dir, self.sealed):
            if path.exists():
                path.chmod(0o755)
        self.temporary.cleanup()

    def open_invocation(self):
        controller = MODULE.HeldFile.open(
            self.controller,
            maximum=MODULE.MAX_CONTROLLER,
            policy=self.policy,
            operations=self.operations,
            mode=0o555,
            immutable=True,
        )
        return MODULE._authenticate_runtime_invocation(
            self.executable,
            self.launcher,
            str(self.launcher),
            str(self.executable),
            self.receipt,
            controller=controller,
            native_capability=FakeNativeCapability(
                hashlib.sha256(self.launcher_bytes).hexdigest(),
                hashlib.sha256(self.original).hexdigest(),
            ),
            policy=self.policy,
            operations=self.operations,
        )

    def test_watch_allows_only_attrib_on_the_executed_runtime_leaf(self) -> None:
        watch = mock.Mock()
        with mock.patch.object(
            MODULE.VnodeWatch,
            "open",
            return_value=watch,
        ) as open_watch:
            invocation = self.open_invocation()
        try:
            watched = set(open_watch.call_args.args[0])
            executable_descriptors = invocation.executable.watch_descriptors()
            self.assertIn(invocation.executable.fd, watched)
            self.assertTrue(set(executable_descriptors[1:]).issubset(watched))
            self.assertEqual(
                open_watch.call_args.kwargs["allow_attrib"],
                (invocation.executable.fd,),
            )
            self.assertEqual(
                open_watch.call_args.kwargs["allow_write"],
                (invocation.controller.directory.fd,),
            )
            self.assertIn(invocation.controller.fd, watched)
            for launcher in invocation.launchers.values():
                self.assertIn(launcher.fd, watched)
        finally:
            invocation.close()
        watch.validate.assert_called_once_with("ReleasePython invocation custody")
        watch.close.assert_called_once_with()

    def test_watch_allows_write_only_on_retained_receipt_parent_descriptors(
        self,
    ) -> None:
        watch = mock.Mock()
        with (
            mock.patch.object(MODULE, "RECEIPT_PATH", self.root / "receipt.json"),
            mock.patch.object(
                MODULE.VnodeWatch,
                "open",
                return_value=watch,
            ) as open_watch,
        ):
            invocation = self.open_invocation()
        try:
            expected = {invocation.controller.directory.fd}
            for directory in (
                invocation.executable.directory,
                *(launcher.directory for launcher in invocation.launchers.values()),
            ):
                descriptor = MODULE._retained_ancestor_descriptor(directory, self.root)
                self.assertIsNotNone(descriptor)
                expected.add(descriptor)
            self.assertEqual(
                set(open_watch.call_args.kwargs["allow_write"]),
                expected,
            )
        finally:
            invocation.close()

    def test_vnode_attrib_exception_rejects_every_other_event(self) -> None:
        queue = mock.Mock()
        watch = MODULE.VnodeWatch(queue, {31: (1, 2)}, {41: (3, 4)})
        with mock.patch.object(
            MODULE.os,
            "fstat",
            side_effect=lambda descriptor: mock.Mock(
                st_dev={31: 1, 41: 3}[descriptor],
                st_ino={31: 2, 41: 4}[descriptor],
            ),
        ):
            for descriptor, flags in (
                (31, MODULE.select.KQ_NOTE_ATTRIB),
                (41, MODULE.select.KQ_NOTE_WRITE),
            ):
                queue.control.return_value = [
                    mock.Mock(ident=descriptor, fflags=flags)
                ]
                watch.validate("exact event")
        for descriptor, flags in (
            (32, MODULE.select.KQ_NOTE_ATTRIB),
            (42, MODULE.select.KQ_NOTE_WRITE),
            (31, MODULE.select.KQ_NOTE_WRITE),
            (41, MODULE.select.KQ_NOTE_ATTRIB),
            (
                31,
                MODULE.select.KQ_NOTE_ATTRIB | MODULE.select.KQ_NOTE_WRITE,
            ),
        ):
            with self.subTest(descriptor=descriptor, flags=flags):
                queue.control.return_value = [
                    mock.Mock(ident=descriptor, fflags=flags)
                ]
                with self.assertRaisesRegex(MODULE.ProvisionError, "changed"):
                    watch.validate("hostile event")
        queue.control.return_value = [
            mock.Mock(ident=41, fflags=MODULE.select.KQ_NOTE_WRITE)
        ]
        with mock.patch.object(
            MODULE.os,
            "fstat",
            return_value=mock.Mock(st_dev=30, st_ino=40),
        ):
            with self.assertRaisesRegex(MODULE.ProvisionError, "descriptor changed"):
                watch.validate("swapped event fd")

    def test_legacy_receipt_uses_retained_replacement_runtime(self) -> None:
        legacy = json.loads(self.receipt)
        live_launcher_tree = legacy["launcher_tree_sha256"]
        legacy["contract"] = "winsvpn-macos-release-python-runtime-v1"
        legacy["schema_version"] = 1
        legacy["executable_sha256"] = "a1" * 32
        legacy["launcher_tree_sha256"] = "a2" * 32
        legacy["launcher_identity_sha256"] = "a3" * 32
        legacy["launcher_dir_identity"] = "1:2:0:0:555:1:2:3"
        controller = MODULE.HeldFile.open(
            self.controller,
            maximum=MODULE.MAX_CONTROLLER,
            policy=self.policy,
            operations=self.operations,
            mode=0o555,
            immutable=True,
        )
        invocation = MODULE._authenticate_runtime_invocation(
            self.executable,
            self.launcher,
            str(self.launcher),
            str(self.executable),
            MODULE.canonical_bytes(legacy),
            controller=controller,
            native_capability=FakeNativeCapability(
                hashlib.sha256(self.launcher_bytes).hexdigest(),
                hashlib.sha256(self.original).hexdigest(),
                live_launcher_tree,
            ),
            policy=self.policy,
            operations=self.operations,
        )
        invocation.close()

    def test_arbitrary_python_and_symlink_are_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.ProvisionError, "fixed ReleasePython"):
            MODULE._authenticate_runtime_invocation(
                self.executable,
                self.launcher,
                sys.executable,
                str(self.executable),
                self.receipt,
                controller=MODULE.HeldFile.open(
                    self.controller,
                    maximum=MODULE.MAX_CONTROLLER,
                    policy=self.policy,
                    operations=self.operations,
                    mode=0o555,
                    immutable=True,
                ),
                native_capability=FakeNativeCapability(
                    hashlib.sha256(self.launcher_bytes).hexdigest(),
                    hashlib.sha256(self.original).hexdigest(),
                ),
                policy=self.policy,
                operations=self.operations,
            )
        self.binary_dir.chmod(0o755)
        self.executable.unlink()
        self.executable.symlink_to(sys.executable)
        self.binary_dir.chmod(0o555)
        with self.assertRaisesRegex(MODULE.ProvisionError, "custody"):
            self.open_invocation()

    def test_reported_base_executable_substitution_is_rejected(self) -> None:
        controller = MODULE.HeldFile.open(
            self.controller,
            maximum=MODULE.MAX_CONTROLLER,
            policy=self.policy,
            operations=self.operations,
            mode=0o555,
            immutable=True,
        )
        with self.assertRaisesRegex(MODULE.ProvisionError, "underlying Mach-O"):
            MODULE._authenticate_runtime_invocation(
                self.executable,
                self.launcher,
                str(self.launcher),
                sys.executable,
                self.receipt,
                controller=controller,
                native_capability=FakeNativeCapability(
                    hashlib.sha256(self.launcher_bytes).hexdigest(),
                    hashlib.sha256(self.original).hexdigest(),
                ),
                policy=self.policy,
                operations=self.operations,
            )

    def test_unexpected_launcher_entry_is_rejected(self) -> None:
        self.launcher_dir.chmod(0o755)
        extra = self.launcher_dir / "python-hostile"
        extra.write_bytes(self.launcher_bytes)
        extra.chmod(0o555)
        self.launcher_dir.chmod(0o555)
        with self.assertRaisesRegex(MODULE.ProvisionError, "unexpected entries"):
            self.open_invocation()

    def test_parent_swap_restore_is_detected(self) -> None:
        invocation = self.open_invocation()
        saved = self.sealed / "bin.saved"
        try:
            self.sealed.chmod(0o755)
            self.binary_dir.rename(saved)
            self.binary_dir.mkdir()
            self.executable.write_bytes(self.original)
            self.executable.chmod(0o555)
            self.binary_dir.chmod(0o555)
            self.binary_dir.chmod(0o755)
            self.executable.unlink()
            self.binary_dir.rmdir()
            saved.rename(self.binary_dir)
            self.sealed.chmod(0o555)
            with self.assertRaisesRegex(MODULE.ProvisionError, "changed while retained"):
                invocation.validate()
        finally:
            invocation.close()

    def test_in_place_replacement_restore_is_detected(self) -> None:
        invocation = self.open_invocation()
        try:
            self.executable.chmod(0o755)
            self.executable.write_bytes(b"substituted release python bytes\n")
            self.executable.write_bytes(self.original)
            self.executable.chmod(0o555)
            with self.assertRaisesRegex(MODULE.ProvisionError, "changed while retained"):
                invocation.validate()
        finally:
            invocation.close()

    def assert_in_place_restore_is_detected(self, target: Path, original: bytes) -> None:
        invocation = self.open_invocation()
        try:
            target.chmod(0o755)
            target.write_bytes(b"substituted invocation bytes\n")
            target.write_bytes(original)
            target.chmod(0o555)
            with self.assertRaisesRegex(MODULE.ProvisionError, "changed while retained"):
                invocation.validate()
        finally:
            invocation.close()

    def test_launcher_in_place_restore_is_detected(self) -> None:
        self.assert_in_place_restore_is_detected(self.launcher, self.launcher_bytes)

    def test_launcher_alias_in_place_restore_is_detected(self) -> None:
        self.assert_in_place_restore_is_detected(
            self.launcher_alias, self.launcher_bytes
        )

    def test_controller_in_place_restore_is_detected(self) -> None:
        self.assert_in_place_restore_is_detected(
            self.controller, b"reviewed owner provision controller\n"
        )

    def test_launcher_parent_swap_restore_is_detected(self) -> None:
        invocation = self.open_invocation()
        saved = self.sealed / "launcher.saved"
        try:
            self.sealed.chmod(0o755)
            self.launcher_dir.rename(saved)
            self.launcher_dir.mkdir()
            self.launcher_dir.rmdir()
            saved.rename(self.launcher_dir)
            self.sealed.chmod(0o555)
            with self.assertRaisesRegex(MODULE.ProvisionError, "changed while retained"):
                invocation.validate()
        finally:
            invocation.close()


@unittest.skipUnless(sys.platform == "darwin", "macOS vnode custody is required")
class OwnerProvisionDependencyCustodyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wins-release-python-dependencies-", dir="/private/tmp"
        )
        self.root = Path(self.temporary.name)
        self.sealed = self.root / "sealed"
        self.dependencies_dir = self.sealed / "dependencies"
        self.dependencies_dir.mkdir(parents=True)
        self.package = self.dependencies_dir / "python-3.14.7-macos11.pkg"
        self.bundle = self.dependencies_dir / "python-3.14.7-macos11.pkg.sigstore"
        self.trusted_root = self.dependencies_dir / "trusted_root.json"
        self.verifier = self.dependencies_dir / "cosign"
        self.identity = "https://github.com/python/release/actions/runs/reviewed"
        self.issuer = MODULE.PYTHON_PACKAGE_OIDC_ISSUER
        self.wheels = [
            self.dependencies_dir / "first-1.0-py3-none-any.whl",
            self.dependencies_dir / "second-1.0-py3-none-any.whl",
        ]
        package_bytes = b"reviewed package bytes\n"
        self.contents = {
            self.package: package_bytes,
            self.bundle: MODULE.canonical_bytes(
                {
                    "certificate_identity": self.identity,
                    "certificate_oidc_issuer": self.issuer,
                    "package_sha256": hashlib.sha256(package_bytes).hexdigest(),
                    "signature": "fixture-signature",
                    "transparency_inclusion_proof": "fixture-proof",
                }
            ),
            self.trusted_root: MODULE.canonical_bytes(
                {"contract": "fixture-sigstore-trusted-root-v1"}
            ),
            self.verifier: (
                b"#!/usr/bin/python3\n"
                b"import hashlib,json,sys\n"
                b"a=sys.argv[1:]\n"
                b"assert len(a)==12 and a[0]=='verify-blob' and a[1]=='--bundle'\n"
                b"assert a[3]=='--trusted-root' and a[5]=='--certificate-identity'\n"
                b"assert a[7]=='--certificate-oidc-issuer' and a[9]=='--offline=true'\n"
                b"assert a[10]=='--max-workers=1'\n"
                b"bundle=json.load(open(a[2],encoding='utf-8'))\n"
                b"root=json.load(open(a[4],encoding='utf-8'))\n"
                b"package=open(a[11],'rb').read()\n"
                b"assert root['contract']=='fixture-sigstore-trusted-root-v1'\n"
                b"assert bundle['certificate_identity']==a[6]\n"
                b"assert bundle['certificate_oidc_issuer']==a[8]\n"
                b"assert bundle['signature'] and bundle['transparency_inclusion_proof']\n"
                b"assert bundle['package_sha256']==hashlib.sha256(package).hexdigest()\n"
                b"print('Verified OK')\n"
            ),
            self.wheels[0]: b"reviewed first wheel bytes\n",
            self.wheels[1]: b"reviewed second wheel bytes\n",
        }
        for path, data in self.contents.items():
            path.write_bytes(data)
            path.chmod(0o555 if path == self.verifier else 0o444)
        self.dependencies_dir.chmod(0o555)
        self.sealed.chmod(0o555)
        self.operations = FakeOperations()
        for path in self.contents:
            self.operations.mark(path, MODULE.SF_IMMUTABLE)
        self.pin_data = MODULE.canonical_bytes(
            {
                "tools": {
                    "python": {
                        "archive_custody": {
                            "darwin_arm64": {
                                "package": {
                                    "path": str(self.package),
                                    "sha256": self.digest(self.package),
                                },
                                "sigstore_bundle": {
                                    "path": str(self.bundle),
                                    "sha256": self.digest(self.bundle),
                                },
                                "sigstore_policy": {
                                    "certificate_identity": self.identity,
                                    "certificate_oidc_issuer": self.issuer,
                                    "verifier_contract": MODULE.SIGSTORE_VERIFIER_CONTRACT,
                                },
                                "sigstore_trusted_root": {
                                    "path": str(self.trusted_root),
                                    "sha256": self.digest(self.trusted_root),
                                },
                                "sigstore_verifier": {
                                    "path": str(self.verifier),
                                    "sha256": self.digest(self.verifier),
                                },
                                "wheel_count": len(self.wheels),
                                "wheels": {
                                    str(index): {
                                        "path": str(path),
                                        "sha256": self.digest(path),
                                    }
                                    for index, path in enumerate(self.wheels)
                                },
                            }
                        }
                    }
                }
            }
        )
        self.candidate = {
            "package_sha256": self.digest(self.package),
            "package_signature_status": "Status: signed fixture",
            "wheel_count": len(self.wheels),
            "wheels": [
                {"name": path.name, "sha256": self.digest(path)}
                for path in self.wheels
            ],
        }

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        for path in (self.dependencies_dir, self.sealed):
            if path.exists():
                path.chmod(0o755)
        self.temporary.cleanup()

    def open_dependencies(self):
        return MODULE.HeldDependencies.open(
            self.pin_data,
            self.candidate,
            owner_uid=os.getuid(),
            operations=self.operations,
            trusted_root=self.sealed,
            sigstore_path=self.bundle,
            sigstore_sha256=self.digest(self.bundle),
        )

    def test_exact_package_bundle_and_wheels_remain_held(self) -> None:
        dependencies = self.open_dependencies()
        try:
            dependencies.validate()
            self.assertEqual(
                dependencies.pass_fds(),
                tuple(record["fd"] for record in dependencies.child_records()),
            )
        finally:
            dependencies.close()

    def test_package_probe_uses_one_private_description_per_call(self) -> None:
        dependencies = self.open_dependencies()
        try:
            self.assertEqual(os.lseek(dependencies.package.fd, 0, os.SEEK_CUR), 0)
            for _attempt in range(3):
                with MODULE._held_package_probe_descriptor(
                    dependencies.package
                ) as probe:
                    self.assertNotEqual(probe, dependencies.package.fd)
                    self.assertEqual(os.lseek(probe, 0, os.SEEK_CUR), 0)
                    self.assertEqual(
                        os.fstat(probe).st_ino,
                        os.fstat(dependencies.package.fd).st_ino,
                    )
                    self.assertEqual(os.read(probe, 8), self.contents[self.package][:8])
                self.assertEqual(
                    os.lseek(dependencies.package.fd, 0, os.SEEK_CUR), 0
                )
            dependencies.validate()
        finally:
            dependencies.close()

    def test_package_probe_rejects_digest_mismatch_and_closes_descriptor(self) -> None:
        dependencies = self.open_dependencies()
        try:
            before = len(os.listdir("/dev/fd"))
            with (
                mock.patch.object(MODULE, "_digest_fd_pread", return_value="00" * 32),
                self.assertRaisesRegex(MODULE.ProvisionError, "bytes are not retained"),
            ):
                with MODULE._held_package_probe_descriptor(dependencies.package):
                    self.fail("digest-mismatched package probe was yielded")
            self.assertEqual(len(os.listdir("/dev/fd")), before)
        finally:
            dependencies.close()

    def test_pretty_pin_manifest_uses_the_same_strict_json_scanner(self) -> None:
        canonical = MODULE._json(
            self.pin_data,
            "canonical dependency pin manifest",
            maximum=MODULE.MAX_PLAN,
        )
        self.pin_data = (
            json.dumps(canonical, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
        ).encode("ascii")
        self.assertEqual(
            canonical,
            MODULE._json(
                self.pin_data,
                "pretty dependency pin manifest",
                maximum=MODULE.MAX_PLAN,
                canonical=False,
            ),
        )
        with mock.patch.object(
            MODULE,
            "_json",
            side_effect=MODULE.ProvisionError("pin parser sentinel"),
        ) as parser:
            with self.assertRaisesRegex(MODULE.ProvisionError, "pin parser sentinel"):
                self.open_dependencies()
        parser.assert_called_once_with(
            self.pin_data,
            "dependency pin manifest",
            maximum=MODULE.MAX_PLAN,
            canonical=False,
        )
        for data, error in (
            (b'{"tools":{},"tools":{}}\n', "duplicate JSON"),
            (b'{"tools":NaN}\n', "non-finite JSON"),
        ):
            with self.subTest(error=error):
                with self.assertRaisesRegex(MODULE.ProvisionError, error):
                    MODULE._json(
                        data,
                        "hostile dependency pin manifest",
                        maximum=MODULE.MAX_PLAN,
                        canonical=False,
                    )

    def test_arbitrary_pinned_sigstore_text_is_cryptographically_rejected(self) -> None:
        self.bundle.chmod(0o644)
        self.bundle.write_bytes(b"reviewed arbitrary text is not a Sigstore bundle\n")
        self.bundle.chmod(0o444)
        manifest = json.loads(self.pin_data)
        custody = manifest["tools"]["python"]["archive_custody"]["darwin_arm64"]
        custody["sigstore_bundle"]["sha256"] = self.digest(self.bundle)
        self.pin_data = MODULE.canonical_bytes(manifest)
        with self.assertRaisesRegex(
            MODULE.ProvisionError,
            "Sigstore certificate, transparency, signature, or package digest",
        ):
            self.open_dependencies()

    def test_extra_pinned_wheel_key_is_rejected(self) -> None:
        manifest = json.loads(self.pin_data)
        wheels = manifest["tools"]["python"]["archive_custody"]["darwin_arm64"][
            "wheels"
        ]
        wheels["999"] = dict(wheels["0"])
        self.pin_data = MODULE.canonical_bytes(manifest)
        with self.assertRaisesRegex(
            MODULE.ProvisionError, "wheel pin keys are not exact"
        ):
            self.open_dependencies()

    def test_sigstore_policy_refuses_non_https_or_injected_verifier(self) -> None:
        manifest = json.loads(self.pin_data)
        policy = manifest["tools"]["python"]["archive_custody"]["darwin_arm64"][
            "sigstore_policy"
        ]
        policy["certificate_oidc_issuer"] = "http://attacker.invalid"
        self.pin_data = MODULE.canonical_bytes(manifest)
        with self.assertRaisesRegex(
            MODULE.ProvisionError, "exact reviewed issuer"
        ):
            self.open_dependencies()

    def test_sigstore_policy_accepts_only_the_exact_reviewed_issuer(self) -> None:
        policy = {
            "certificate_identity": self.identity,
            "certificate_oidc_issuer": MODULE.PYTHON_PACKAGE_OIDC_ISSUER,
            "verifier_contract": MODULE.SIGSTORE_VERIFIER_CONTRACT,
        }
        self.assertEqual(MODULE._sigstore_policy(policy), policy)
        for issuer in (
            "http://github.com/login/oauth",
            "https://github.example/login/oauth",
            "https://github.com/login/oauth/",
            "https://github.com/login/oauth?reviewed=true",
            "https://github.com%2Flogin%2Foauth",
        ):
            with self.subTest(issuer=issuer):
                with self.assertRaisesRegex(
                    MODULE.ProvisionError, "exact reviewed issuer"
                ):
                    MODULE._sigstore_policy(
                        {**policy, "certificate_oidc_issuer": issuer}
                    )

    def test_sigstore_verifier_receives_exact_held_paths(self) -> None:
        verifier = mock.Mock(path=self.verifier, fd=31)
        trusted_root = mock.Mock(path=self.trusted_root, fd=32)
        bundle = mock.Mock(path=self.bundle, fd=33)
        package = mock.Mock(path=self.package, fd=34)
        policy = {
            "certificate_identity": self.identity,
            "certificate_oidc_issuer": MODULE.PYTHON_PACKAGE_OIDC_ISSUER,
            "verifier_contract": MODULE.SIGSTORE_VERIFIER_CONTRACT,
        }
        with mock.patch.object(
            MODULE,
            "_run_bounded_child",
            return_value=(0, b"Verified OK\n", b""),
        ) as runner:
            MODULE._verify_sigstore_bundle(
                verifier,
                trusted_root,
                bundle,
                package,
                policy,
            )
        argv = runner.call_args.args[0]
        self.assertEqual(argv[0], str(self.verifier))
        self.assertEqual(argv[3], str(self.bundle))
        self.assertEqual(argv[5], str(self.trusted_root))
        self.assertEqual(argv[-1], str(self.package))
        self.assertFalse(any(value.startswith("/dev/fd/") for value in argv))
        self.assertNotIn("pass_fds", runner.call_args.kwargs)

    def test_watch_allows_only_attrib_on_the_executed_sigstore_leaf(self) -> None:
        watch = mock.Mock()
        with mock.patch.object(
            MODULE.VnodeWatch,
            "open",
            return_value=watch,
        ) as open_watch:
            dependencies = self.open_dependencies()
        try:
            watched = set(open_watch.call_args.args[0])
            verifier_descriptors = dependencies.sigstore_verifier.watch_descriptors()
            self.assertIn(dependencies.sigstore_verifier.fd, watched)
            self.assertTrue(set(verifier_descriptors[1:]).issubset(watched))
            self.assertEqual(
                open_watch.call_args.kwargs["allow_attrib"],
                (dependencies.sigstore_verifier.fd,),
            )
            for artifact in (
                dependencies.package,
                dependencies.sigstore_bundle,
                dependencies.sigstore_trusted_root,
                *dependencies.wheels,
            ):
                self.assertIn(artifact.fd, watched)
        finally:
            dependencies.close()
        watch.validate.assert_called_once_with(
            "ReleasePython package and wheel custody"
        )
        watch.close.assert_called_once_with()

    def test_dependency_without_system_immutable_flag_is_rejected(self) -> None:
        self.operations.mark(self.package, 0)
        with self.assertRaisesRegex(MODULE.ProvisionError, "system immutable"):
            self.open_dependencies()

    def test_mutable_dependency_parent_is_owner_blocked(self) -> None:
        self.dependencies_dir.chmod(0o755)
        with self.assertRaisesRegex(MODULE.ProvisionError, "ancestor custody"):
            self.open_dependencies()

    def test_current_downloads_ancestry_is_owner_blocked_without_opening_package(self) -> None:
        owner_uid = os.getuid()
        policy = MODULE.CustodyPolicy(
            uid=owner_uid,
            gid=os.getgid(),
            require_immutable=False,
            strict_ancestry=True,
            trusted_root=Path("/"),
            exact_ancestor_owner=False,
            allowed_ancestor_uids=frozenset({0, owner_uid}),
            forbidden_writable_uid=owner_uid,
        )
        with self.assertRaisesRegex(MODULE.ProvisionError, "ancestor custody"):
            MODULE.HeldDirectory.open(Path("/Users/owner/Downloads"), policy)

    def test_production_dependency_paths_are_exactly_content_addressed(self) -> None:
        with self.assertRaisesRegex(
            MODULE.ProvisionError, "fixed content-addressed custody"
        ):
            MODULE.HeldDependencies.open(
                self.pin_data,
                self.candidate,
                owner_uid=os.getuid(),
                operations=self.operations,
                trusted_root=Path("/"),
            )
        self.assertEqual(
            MODULE.SIGSTORE_BUNDLE_PATH,
            MODULE.INPUT_CUSTODY_ROOT
            / MODULE.SIGSTORE_BUNDLE_SHA256
            / "python-3.14.7-macos11.pkg.sigstore",
        )
        self.assertNotIn("Downloads", str(MODULE.SIGSTORE_BUNDLE_PATH))

    def test_package_wheel_and_bundle_leaf_swap_restore_are_detected(self) -> None:
        for target in (self.package, self.bundle, *self.wheels):
            with self.subTest(target=target.name):
                dependencies = self.open_dependencies()
                saved = target.with_name(target.name + ".saved")
                try:
                    self.dependencies_dir.chmod(0o755)
                    target.rename(saved)
                    target.write_bytes(self.contents[target])
                    target.chmod(0o444)
                    target.unlink()
                    saved.rename(target)
                    self.dependencies_dir.chmod(0o555)
                    with self.assertRaisesRegex(
                        MODULE.ProvisionError, "changed while retained"
                    ):
                        dependencies.validate()
                finally:
                    dependencies.close()

    def test_dependency_parent_swap_restore_is_detected(self) -> None:
        dependencies = self.open_dependencies()
        saved = self.sealed / "dependencies.saved"
        try:
            self.sealed.chmod(0o755)
            self.dependencies_dir.rename(saved)
            self.dependencies_dir.mkdir()
            self.dependencies_dir.rmdir()
            saved.rename(self.dependencies_dir)
            self.sealed.chmod(0o555)
            with self.assertRaisesRegex(MODULE.ProvisionError, "changed while retained"):
                dependencies.validate()
        finally:
            dependencies.close()

    def test_package_and_wheel_in_place_restore_are_detected(self) -> None:
        for target in (self.package, self.wheels[0]):
            with self.subTest(target=target.name):
                dependencies = self.open_dependencies()
                try:
                    target.chmod(0o644)
                    target.write_bytes(b"substitute dependency bytes\n")
                    target.write_bytes(self.contents[target])
                    target.chmod(0o444)
                    with self.assertRaisesRegex(
                        MODULE.ProvisionError, "changed while retained"
                    ):
                        dependencies.validate()
                finally:
                    dependencies.close()

    def test_dependency_swap_during_publication_rolls_back(self) -> None:
        dependencies = self.open_dependencies()
        transaction = Fixture()
        original_receipt = transaction.paths.receipt.read_bytes()
        original_authority = transaction.paths.authority.read_bytes()

        def swap_after_preflight(point: str) -> None:
            if point != "preflight-reauthenticated":
                return
            self.package.chmod(0o644)
            self.package.write_bytes(b"synchronized substitute package bytes\n")
            self.package.write_bytes(self.contents[self.package])
            self.package.chmod(0o444)

        try:
            with self.assertRaisesRegex(MODULE.ProvisionError, "changed while retained"):
                transaction.apply(
                    dependency_custody=dependencies,
                    crash_hook=swap_after_preflight,
                )
            self.assertEqual(transaction.paths.receipt.read_bytes(), original_receipt)
            self.assertEqual(transaction.paths.authority.read_bytes(), original_authority)
        finally:
            transaction.close()
            dependencies.close()


class OwnerProvisionBoundedChildTest(unittest.TestCase):
    def run_child(self, source: str, *arguments: str, timeout: float = 5.0):
        return MODULE._run_bounded_child(
            [sys.executable, "-I", "-S", "-c", source, *arguments],
            env={"PATH": "/usr/bin:/bin"},
            timeout=timeout,
        )

    def test_stdout_and_stderr_floods_are_rejected_at_exact_caps(self) -> None:
        for descriptor, label in ((1, "stdout"), (2, "stderr")):
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.ProvisionError, f"{label} exceeded"
            ):
                self.run_child(
                    f"import os;os.write({descriptor},b'x'*({MODULE.MAX_CHILD_STDOUT + 1}))"
                )

    def test_child_and_grandchild_are_cleaned_after_child_exit(self) -> None:
        returncode, stdout, stderr = self.run_child(
            "import subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(30)']);"
            "print(p.pid,flush=True)"
        )
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr, b"")
        grandchild = int(stdout.strip())
        for _attempt in range(50):
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail("grandchild survived bounded child cleanup")

    def test_timeout_kills_child_and_grandchild_process_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bounded-child-", dir="/private/tmp") as root:
            marker = Path(root) / "grandchild.pid"
            source = (
                "import pathlib,subprocess,sys,time;"
                "p=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(30)']);"
                "pathlib.Path(sys.argv[1]).write_text(str(p.pid),encoding='ascii');"
                "time.sleep(30)"
            )
            with self.assertRaisesRegex(MODULE.ProvisionError, "absolute deadline"):
                self.run_child(source, str(marker), timeout=0.25)
            grandchild = int(marker.read_text(encoding="ascii"))
            for _attempt in range(50):
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("grandchild survived deadline cleanup")

    def test_child_crash_returns_without_capture_all_or_hang(self) -> None:
        returncode, stdout, stderr = self.run_child(
            "import os;os.write(2,b'crash\\n');os._exit(73)"
        )
        self.assertEqual(returncode, 73)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"crash\n")

    def test_preexec_stall_is_deadline_bounded_and_reaped(self) -> None:
        marker_read, marker_write = os.pipe()

        def stall_before_exec() -> None:
            os.write(marker_write, os.getpid().to_bytes(8, "big"))
            time.sleep(30)

        started = time.monotonic()
        try:
            with self.assertRaisesRegex(MODULE.ProvisionError, "absolute deadline"):
                MODULE._run_bounded_child(
                    [sys.executable, "-I", "-S", "-c", "pass"],
                    env={"PATH": "/usr/bin:/bin"},
                    pass_fds=(marker_write,),
                    preexec_fn=stall_before_exec,
                    timeout=0.25,
                )
        finally:
            os.close(marker_write)
        elapsed = time.monotonic() - started
        marker = os.read(marker_read, 9)
        os.close(marker_read)
        self.assertEqual(len(marker), 8)
        child = int.from_bytes(marker, "big")
        self.assertLess(elapsed, 5.0)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)

    def test_production_nproc_limit_denies_child_fork(self) -> None:
        source = (
            "import os;"
            "\ntry: os.fork()"
            "\nexcept OSError as exc: print(exc.errno,flush=True)"
            "\nelse: os._exit(91)"
        )
        returncode, stdout, stderr = MODULE._run_bounded_child(
            [sys.executable, "-I", "-S", "-c", source],
            env={"PATH": "/usr/bin:/bin"},
            forbid_descendants=True,
            timeout=5.0,
        )
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout, f"{errno.EAGAIN}\n".encode("ascii"))
        self.assertEqual(stderr, b"")

    def test_repeated_fast_exit_never_waits_for_full_deadline(self) -> None:
        started = time.monotonic()
        for _attempt in range(20):
            returncode, stdout, stderr = self.run_child("pass", timeout=1.0)
            self.assertEqual((returncode, stdout, stderr), (0, b"", b""))
        self.assertLess(time.monotonic() - started, 5.0)

    def test_creation_timer_state_is_restored_and_active_timer_is_refused(self) -> None:
        prior_handler = MODULE.signal.getsignal(MODULE.signal.SIGALRM)
        prior_timer = MODULE.signal.getitimer(MODULE.signal.ITIMER_REAL)
        self.assertEqual(prior_timer, (0.0, 0.0))
        self.assertEqual(self.run_child("pass"), (0, b"", b""))
        self.assertIs(MODULE.signal.getsignal(MODULE.signal.SIGALRM), prior_handler)
        self.assertEqual(MODULE.signal.getitimer(MODULE.signal.ITIMER_REAL), prior_timer)
        MODULE.signal.setitimer(MODULE.signal.ITIMER_REAL, 30.0, 0.0)
        try:
            with self.assertRaisesRegex(MODULE.ProvisionError, "active real-time"):
                self.run_child("pass")
        finally:
            MODULE.signal.setitimer(MODULE.signal.ITIMER_REAL, 0.0, 0.0)
        self.assertIs(MODULE.signal.getsignal(MODULE.signal.SIGALRM), prior_handler)

    def test_descendant_inventory_exit_race_is_not_a_false_failure(self) -> None:
        class FakeFunction:
            argtypes: list[object] = []
            restype: object = None

            def __call__(self, _pid: int, _values: object, _size: int) -> int:
                return -1

        class FakeLibrary:
            proc_listchildpids = FakeFunction()

        with mock.patch.object(MODULE.ctypes, "CDLL", return_value=FakeLibrary()), mock.patch.object(
            MODULE.ctypes, "get_errno", return_value=errno.ESRCH
        ):
            self.assertEqual(MODULE._darwin_child_pids(12345), set())
        with mock.patch.object(MODULE.ctypes, "CDLL", return_value=FakeLibrary()), mock.patch.object(
            MODULE.ctypes, "get_errno", return_value=errno.EIO
        ), self.assertRaisesRegex(MODULE.ProvisionError, "inventory failed closed"):
            MODULE._darwin_child_pids(12345)


class OwnerProvisionStaticTest(unittest.TestCase):
    @staticmethod
    def package_signature_stream() -> bytes:
        return (
            'Package "python-3.14.7-macos11.pkg":\n'
            "   Status: signed by a developer certificate issued by Apple for distribution\n"
            "   Notarization: trusted by the Apple notary service\n"
            "   Signed with a trusted timestamp on: 2026-08-05 11:23:15 AM +0000\n"
            "   Certificate Chain:\n"
            "    1. Developer ID Installer: Python Software Foundation (BMM5U3QVKW)\n"
            "       Expires: 2030-05-21 4:16:18 PM +0000\n"
        ).encode("utf-8")

    def test_package_signature_parser_accepts_only_exact_live_prefix(self) -> None:
        stream = self.package_signature_stream()
        status = "Status: signed by a developer certificate issued by Apple for distribution"
        self.assertTrue(
            MODULE._package_signature_stream_is_current_psf_trust(
                stream,
                b"",
                package_name="python-3.14.7-macos11.pkg",
                expected_status=status,
            )
        )
        hostile = (
            stream.replace(b"   Status:", b"Status:", 1),
            stream.replace(b"trusted by", b"rejected by", 1),
            stream.replace(b"trusted timestamp", b"timestamp", 1),
            stream.replace(b"BMM5U3QVKW", b"AAAAAAAAAA", 1),
            stream.replace(b"Package \"python", b"Package \"other", 1),
            stream.replace(b"\n", b"\r\n"),
            stream[:-1],
            stream + b"\0",
            stream + stream.split(b"\n", 2)[1] + b"\n",
        )
        for value in hostile:
            with self.subTest(value=value[:80]):
                self.assertFalse(
                    MODULE._package_signature_stream_is_current_psf_trust(
                        value,
                        b"",
                        package_name="python-3.14.7-macos11.pkg",
                        expected_status=status,
                    )
                )
        self.assertFalse(
            MODULE._package_signature_stream_is_current_psf_trust(
                stream,
                b"diagnostic\n",
                package_name="python-3.14.7-macos11.pkg",
                expected_status=status,
            )
        )

    def test_bounded_child_failure_details_are_bounded_and_escaped(self) -> None:
        stdout = b"unexpected output\n"
        terminal = b"BlockingIOError: [Errno 35] Resource temporarily unavailable\n"
        stderr = b"line one\ncontrol:\0\xff\n" + b"x" * 2048 + terminal
        details = MODULE._bounded_child_failure_details(17, stdout, stderr)
        self.assertIn("returncode=17", details)
        self.assertIn(f"stdout_bytes={len(stdout)}", details)
        self.assertIn(f"stdout_sha256={hashlib.sha256(stdout).hexdigest()}", details)
        self.assertIn(f"stderr_bytes={len(stderr)}", details)
        self.assertIn(f"stderr_sha256={hashlib.sha256(stderr).hexdigest()}", details)
        self.assertIn(r"control:\\x00\\xff\\n", details)
        self.assertIn("BlockingIOError", details)
        self.assertIn("bytes omitted", details)
        self.assertNotIn("\0", details)
        self.assertEqual(
            details, MODULE._bounded_child_failure_details(17, stdout, stderr)
        )
        self.assertLess(len(details), 7000)

        for length in (0, 1, 511, 512, 513, 1023, 1024, 1025, 3236):
            value = bytes(index % 256 for index in range(length))
            with self.subTest(length=length):
                result = MODULE._bounded_child_failure_details(1, b"", value)
                self.assertIn(f"stderr_bytes={length}", result)
                self.assertIn(hashlib.sha256(value).hexdigest(), result)
                self.assertEqual(result, MODULE._bounded_child_failure_details(1, b"", value))

    def test_held_receipt_exec_surface_is_exact(self) -> None:
        source = (ROOT / "tools/macos_release_python_runtime_receipt.py").read_bytes()
        MODULE._validate_reauthentication_exec_surface(source)
        hostile = (
            source + b'\nimport ctypes\n',
            source + b'\nos.system("/usr/bin/id")\n',
            source + b'\nsubprocess.Popen(["/usr/bin/true"])\n',
            source + b'\nsubprocess.run(["/usr/bin/true"])\n',
            source + b'\nexec("pass")\n',
            source + b'\nos.posix_spawn("/usr/bin/true", ["true"], {})\n',
        )
        for value in hostile:
            with self.subTest(suffix=value[len(source) :]), self.assertRaisesRegex(
                MODULE.ProvisionError,
                r"(?:import surface|process surface|subprocess surface|subprocess gate|dynamic execution)",
            ):
                MODULE._validate_reauthentication_exec_surface(value)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS pkgutil")
    def test_package_signature_parser_accepts_live_pinned_pkgutil_fd_stream(
        self,
    ) -> None:
        pins = json.loads((ROOT / "tools" / "toolchain-pins.json").read_text())
        package = Path(
            pins["tools"]["python"]["archive_custody"]["darwin_arm64"]["package"][
                "path"
            ]
        )
        if not package.is_file():
            self.skipTest("pinned Python package is absent")
        descriptor = os.open(package, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            completed = subprocess.run(
                ["/usr/sbin/pkgutil", "--check-signature", f"/dev/fd/{descriptor}"],
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                pass_fds=(descriptor,),
                capture_output=True,
                timeout=30,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(
            MODULE._package_signature_stream_is_current_psf_trust(
                completed.stdout,
                completed.stderr,
                package_name=package.name,
                expected_status=(
                    "Status: signed by a developer certificate issued by Apple "
                    "for distribution"
                ),
            )
        )

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS pkgutil")
    def test_live_pinned_pkgutil_uses_fresh_probe_for_repeated_checks(self) -> None:
        pins = json.loads((ROOT / "tools" / "toolchain-pins.json").read_text())
        package_record = pins["tools"]["python"]["archive_custody"]["darwin_arm64"][
            "package"
        ]
        package = Path(package_record["path"])
        if not package.is_file():
            self.skipTest("pinned Python package is absent")
        info = os.stat(package, follow_symlinks=False)
        policy = MODULE.CustodyPolicy(
            uid=info.st_uid,
            gid=info.st_gid,
            require_immutable=True,
            strict_ancestry=True,
            trusted_root=Path("/"),
            exact_ancestor_owner=False,
            allowed_ancestor_uids=frozenset({0}),
            forbidden_writable_uid=os.getuid(),
        )
        held = MODULE.HeldArtifact.open(
            package,
            expected_sha256=package_record["sha256"],
            maximum=MODULE.MAX_PACKAGE,
            policy=policy,
            operations=MODULE.SYSTEM_OPERATIONS,
            allowed_leaf_uids=frozenset({0}),
            mode=0o444,
            immutable=True,
        )
        streams: list[bytes] = []
        try:
            for _attempt in range(2):
                with MODULE._held_package_probe_descriptor(held) as descriptor:
                    completed = subprocess.run(
                        [
                            "/usr/sbin/pkgutil",
                            "--check-signature",
                            f"/dev/fd/{descriptor}",
                        ],
                        env={
                            "LC_ALL": "C",
                            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        },
                        pass_fds=(descriptor,),
                        capture_output=True,
                        timeout=30,
                    )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertTrue(
                    MODULE._package_signature_stream_is_current_psf_trust(
                        completed.stdout,
                        completed.stderr,
                        package_name=package.name,
                        expected_status=(
                            "Status: signed by a developer certificate issued by Apple "
                            "for distribution"
                        ),
                    )
                )
                self.assertEqual(os.lseek(held.fd, 0, os.SEEK_CUR), 0)
                streams.append(completed.stdout)
            self.assertEqual(streams[0], streams[1])
            held.validate()
        finally:
            held.close()

    def test_system_operations_set_flags_fd_prefers_native_fchflags(self) -> None:
        operation = mock.Mock()
        with mock.patch.object(MODULE.os, "fchflags", operation, create=True):
            MODULE.SystemOperations().set_flags_fd(7, stat.UF_IMMUTABLE)
        operation.assert_called_once_with(7, stat.UF_IMMUTABLE)

    def test_system_operations_set_flags_fd_uses_darwin_libc_fallback(self) -> None:
        operation = mock.Mock(return_value=0)
        libc = mock.Mock(fchflags=operation)
        with (
            mock.patch.object(MODULE.os, "fchflags", None, create=True),
            mock.patch.object(MODULE.sys, "platform", "darwin"),
            mock.patch.object(MODULE.ctypes, "CDLL", return_value=libc) as loader,
        ):
            MODULE.SystemOperations().set_flags_fd(11, stat.SF_IMMUTABLE)
        loader.assert_called_once_with(None, use_errno=True)
        self.assertEqual(operation.argtypes, [MODULE.ctypes.c_int, MODULE.ctypes.c_uint])
        self.assertIs(operation.restype, MODULE.ctypes.c_int)
        operation.assert_called_once_with(11, stat.SF_IMMUTABLE)

    def test_system_operations_set_flags_fd_preserves_libc_errno(self) -> None:
        operation = mock.Mock(return_value=-1)
        libc = mock.Mock(fchflags=operation)
        with (
            mock.patch.object(MODULE.os, "fchflags", None, create=True),
            mock.patch.object(MODULE.sys, "platform", "darwin"),
            mock.patch.object(MODULE.ctypes, "CDLL", return_value=libc),
            mock.patch.object(MODULE.ctypes, "get_errno", return_value=9) as get_errno,
        ):
            with self.assertRaises(OSError) as context:
                MODULE.SystemOperations().set_flags_fd(12, 0)
        get_errno.assert_called_once_with()
        self.assertEqual(context.exception.errno, 9)
        self.assertEqual(context.exception.strerror, os.strerror(9))

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin fchflags(2)")
    def test_system_operations_set_flags_fd_uses_real_darwin_libc(self) -> None:
        with tempfile.NamedTemporaryFile() as temporary:
            before = os.fstat(temporary.fileno()).st_flags
            with mock.patch.object(MODULE.os, "fchflags", None, create=True):
                MODULE.SystemOperations().set_flags_fd(temporary.fileno(), before)
            self.assertEqual(os.fstat(temporary.fileno()).st_flags, before)

    def test_system_operations_set_flags_fd_rejects_invalid_arguments(self) -> None:
        operations = MODULE.SystemOperations()
        invalid = (
            (True, 0, "file descriptor must be"),
            (-1, 0, "file descriptor must be"),
            (0x80000000, 0, "file descriptor must be"),
            (1.0, 0, "file descriptor must be"),
            (1, True, "file flags must be"),
            (1, -1, "file flags must be"),
            (1, 0x100000000, "file flags must be"),
            (1, 0.0, "file flags must be"),
        )
        operation = mock.Mock()
        with mock.patch.object(MODULE.os, "fchflags", operation, create=True):
            for fd, flags, message in invalid:
                with self.subTest(fd=fd, flags=flags):
                    with self.assertRaisesRegex(MODULE.ProvisionError, message):
                        operations.set_flags_fd(fd, flags)
        operation.assert_not_called()

    def test_system_operations_set_flags_fd_refuses_non_darwin_fallback(self) -> None:
        with (
            mock.patch.object(MODULE.os, "fchflags", None, create=True),
            mock.patch.object(MODULE.sys, "platform", "linux"),
        ):
            with self.assertRaisesRegex(MODULE.ProvisionError, "fchflags is unavailable"):
                MODULE.SystemOperations().set_flags_fd(1, 0)

    def test_authenticated_orig_argv_binds_executed_runtime_python(self) -> None:
        source = TOOL.read_text(encoding="ascii")
        expected = "expected_original = [\n        str(RUNTIME_PYTHON),"
        self.assertIn(expected, source)
        self.assertNotIn(
            "expected_original = [\n        str(RUNTIME_APP_PYTHON),",
            source,
        )

    def test_native_runtime_tree_hashes_are_bound_to_active_receipt(self) -> None:
        source = TOOL.read_text(encoding="ascii")
        for field in (
            "runtime_framework_tree_sha256",
            "runtime_vendor_tree_sha256",
            "runtime_launcher_tree_sha256",
        ):
            self.assertIn(field, source)
        self.assertIn("native runtime closure binding mismatch", source)

    def test_ed25519_selftest_and_closure_count(self) -> None:
        MODULE.selftest()
        self.assertEqual(len(MODULE.MIGRATION_CLOSURE_PATHS), 17)

    def test_sequence_one_activation_is_apply_only_and_future_apply_is_normal(
        self,
    ) -> None:
        fixture = Fixture()
        try:
            receipt = MODULE._json(
                fixture.candidate, "activation fixture", maximum=MODULE.MAX_RECEIPT
            )
            receipt["launcher_tree_sha256"] = "a2" * 32
            receipt["launcher_identity_sha256"] = "a3" * 32
            receipt["launcher_dir_identity"] = "fixture-launcher-directory"
            old_closure = {key: "a1" * 32 for key in fixture.closure}
            receipt["custody_closure"] = old_closure
            authority = fixture.make_authority()
            authority["active_sequence"] = 1
            with self.assertRaisesRegex(MODULE.ProvisionError, "restricted to apply"):
                MODULE._validate_active_runtime_receipt(receipt, authority)
            MODULE._validate_active_runtime_receipt(
                receipt, authority, allow_sequence_one_activation=True
            )
            authority["active_sequence"] = 2
            receipt["custody_closure"] = dict(authority["closure"])
            MODULE._validate_active_runtime_receipt(
                receipt, authority, allow_sequence_one_activation=True
            )
            self.assertFalse(
                MODULE._is_sequence_one_activation_receipt(receipt, authority)
            )
        finally:
            fixture.close()

    def test_selftest_and_apply_refuse_initial_publication_residue(self) -> None:
        fixture = Fixture()
        residue = (
            fixture.authority_dir / MODULE.INITIAL_AUTHORITY_JOURNAL_NEXT_NAME
        )
        residue.write_bytes(b"residue\n")
        residue.chmod(0o600)
        authority_dir = MODULE.HeldDirectory.open(
            fixture.authority_dir, fixture.policy
        )
        receipt_dir = MODULE.HeldDirectory.open(fixture.receipt_dir, fixture.policy)
        try:
            with self.assertRaisesRegex(
                MODULE.ProvisionError, "initial-authority publication"
            ):
                MODULE._assert_no_transaction_leftovers(
                    authority_dir, receipt_dir, fixture.paths
                )
        finally:
            receipt_dir.close()
            authority_dir.close()
            fixture.close()
        self.assertIn(
            "_assert_no_transaction_leftovers(",
            inspect.getsource(MODULE._authenticated_selftest),
        )

    def test_v2_active_code_has_no_v1_authority_path(self) -> None:
        tracked = subprocess.run(
            ["/usr/bin/git", "ls-files"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        fossil = {
            "docs/rulings/RELEASEPYTHON_SEALED_PAIR_UPDATER_RULING_20260901.md",
            "docs/rulings/RULINGS.lock",
            "tools/macos_release_python_owner_updater.c",
            "tools/test_macos_release_python_owner_updater.py",
        }
        needle = ("ReleasePythonAuthority/" + "v1").encode("ascii")
        for relative in tracked:
            if relative in fossil:
                continue
            path = ROOT / relative
            if not path.is_file():
                continue
            with self.subTest(relative=relative):
                self.assertNotIn(needle, path.read_bytes())

    def test_activation_keeps_native_runtime_tree_binding(self) -> None:
        invocation_source = inspect.getsource(MODULE._require_production_invocation)
        self.assertIn(
            "receipt=receipt_record,",
            invocation_source,
        )
        self.assertIn(
            "allow_generation_activation=sequence_one_activation,",
            invocation_source,
        )
        consume_source = inspect.getsource(MODULE.NativeCapability.consume)
        tree_block = consume_source.split("receipt_trees =", 1)[1].split(
            "named_controller =", 1
        )[0]
        self.assertNotIn("allow_generation_activation", tree_block)
        self.assertIn(
            'allow_sequence_one_activation=args.action in {"apply", "recover"}',
            inspect.getsource(MODULE.main),
        )

    def test_python314_parser_does_not_require_stdout_fileno(self) -> None:
        output = io.StringIO()
        with mock.patch.object(sys, "stdout", output):
            self.assertIsInstance(MODULE._argument_parser(), MODULE.argparse.ArgumentParser)

    def test_imported_main_refuses_caller_argv(self) -> None:
        error = io.StringIO()
        with mock.patch.object(sys, "stderr", error):
            self.assertEqual(MODULE.main(["selftest"]), 1)
        self.assertIn("refuses caller-supplied argv", error.getvalue())

    def test_authenticated_selftest_has_no_authority_or_dependency_bypass(self) -> None:
        with mock.patch.object(
            MODULE,
            "_require_production_invocation",
            side_effect=MODULE.ProvisionError("missing active authority"),
        ) as require:
            with self.assertRaisesRegex(
                MODULE.ProvisionError, "missing active authority"
            ):
                MODULE._authenticated_selftest()
        require.assert_called_once_with()
        source = inspect.getsource(MODULE._authenticated_selftest)
        self.assertIn("_require_authority_current", source)
        self.assertIn("HeldDependencies.open", source)
        self.assertIn("_parse_candidate_receipt", source)
        self.assertNotIn("authority=None", source)
        self.assertNotIn("receipt=None", source)

    def test_imported_production_apis_refuse_before_filesystem_access(self) -> None:
        with self.assertRaisesRegex(MODULE.ProvisionError, "held ReleasePython"):
            MODULE.apply_transaction(
                Path("/does/not/exist/plan"),
                Path("/does/not/exist/authorization"),
            )
        with self.assertRaisesRegex(MODULE.ProvisionError, "held ReleasePython"):
            MODULE.recover_transaction()

    def test_exact_launcher_environment_rejects_injection_and_drift(self) -> None:
        self.assertNotIn("DYLD_FRAMEWORK_PATH", MODULE.LAUNCHER_ENVIRONMENT)
        self.assertNotIn("DYLD_LIBRARY_PATH", MODULE.LAUNCHER_ENVIRONMENT)
        exact = {
            **MODULE.LAUNCHER_ENVIRONMENT,
            "HOME": "/var/root",
            "LC_CTYPE": "C.UTF-8",
            "TMPDIR": "/private/tmp",
            "__CF_USER_TEXT_ENCODING": "0x0:0:0",
        }
        with mock.patch.dict(os.environ, exact, clear=True):
            MODULE._require_exact_launcher_environment()
        for name, value in (
            ("PYTHONINSPECT", "1"),
            ("DYLD_INSERT_LIBRARIES", "/private/tmp/injected.dylib"),
            ("UNREVIEWED", "1"),
        ):
            with self.subTest(name=name), mock.patch.dict(
                os.environ, {**exact, name: value}, clear=True
            ):
                with self.assertRaisesRegex(
                    MODULE.ProvisionError, "environment|unexpected"
                ):
                    MODULE._require_exact_launcher_environment()
        for value in ("", "0x0:0x0:0x0", "0x1F5:0:0"):
            with self.subTest(user_text=value), mock.patch.dict(
                os.environ,
                {**exact, "__CF_USER_TEXT_ENCODING": value},
                clear=True,
            ):
                with self.assertRaisesRegex(MODULE.ProvisionError, "user-text"):
                    MODULE._require_exact_launcher_environment()
        with mock.patch.dict(
            os.environ,
            {**exact, "PYTHONEXECUTABLE": str(MODULE.RUNTIME_PYTHON)},
            clear=True,
        ):
            with self.assertRaisesRegex(MODULE.ProvisionError, "PYTHONEXECUTABLE"):
                MODULE._require_exact_launcher_environment()

    def test_installed_native_launcher_executes_controller_selftest(self) -> None:
        if not MODULE.OWNER_LAUNCHER_PATH.is_file():
            completed = subprocess.run(
                [
                    sys.executable,
                    str(LAUNCHER_TEST),
                    "NativeLauncherTest.test_real_native_launch_and_live_capability",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return
        completed = subprocess.run(
            [
                str(MODULE.OWNER_LAUNCHER_PATH),
                "selftest",
            ],
            cwd=ROOT,
            env={"HOME": "/var/root", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout, "macOS ReleasePython owner-provision self-test passed\n"
        )

    def test_installed_native_launcher_rejects_python_modes(self) -> None:
        if not MODULE.OWNER_LAUNCHER_PATH.is_file():
            completed = subprocess.run(
                [
                    sys.executable,
                    str(LAUNCHER_TEST),
                    "NativeLauncherTest.test_argv_and_environment_are_exact",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return
        completed = subprocess.run(
            [str(MODULE.OWNER_LAUNCHER_PATH), "-c", "pass"],
            cwd=ROOT,
            env={"HOME": "/var/root", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("argv must be exactly", completed.stderr)

    @unittest.skipUnless(
        MODULE.RUNTIME_LAUNCHER.is_file() and MODULE.RECEIPT_PATH.is_file(),
        "installed ReleasePython launcher or receipt is absent",
    )
    def test_installed_launcher_and_underlying_macho_match_active_receipt(self) -> None:
        receipt = MODULE._json(
            MODULE.RECEIPT_PATH.read_bytes(),
            "installed active runtime receipt",
            maximum=MODULE.MAX_RECEIPT,
        )
        policy = MODULE.CustodyPolicy.production()
        launchers = {
            path.name: MODULE.HeldFile.open(
                path,
                maximum=MODULE.MAX_RUNTIME_LAUNCHER,
                policy=policy,
                operations=MODULE.SYSTEM_OPERATIONS,
                mode=0o555,
                immutable=True,
            )
            for path in (MODULE.RUNTIME_LAUNCHER_ALIAS, MODULE.RUNTIME_LAUNCHER)
        }
        executable = None
        try:
            self.assertEqual(
                MODULE._launcher_tree_hashes(
                    launchers, MODULE.SYSTEM_OPERATIONS
                ),
                (
                    receipt["launcher_tree_sha256"],
                    receipt["launcher_identity_sha256"],
                    receipt["launcher_dir_identity"],
                ),
            )
            executable = MODULE.HeldArtifact.open(
                MODULE.RUNTIME_PYTHON,
                expected_sha256=str(receipt["executable_sha256"]),
                maximum=MODULE.MAX_RUNTIME_EXECUTABLE,
                policy=policy,
                operations=MODULE.SYSTEM_OPERATIONS,
                allowed_leaf_uids=frozenset({0}),
                mode=0o555,
                immutable=True,
            )
            executable.validate()
        finally:
            if executable is not None:
                executable.close()
            for held in launchers.values():
                held.close()

    @unittest.skipUnless(
        MODULE.RUNTIME_LAUNCHER.is_file(), "installed ReleasePython launcher is absent"
    )
    def test_runpy_and_c_execution_are_rejected(self) -> None:
        probe = (
            "import runpy,sys;"
            f"sys.argv=[{str(MODULE.OWNER_PROVISION_PATH)!r},'recover'];"
            f"runpy.run_path({str(TOOL)!r},run_name='__main__')"
        )
        completed = subprocess.run(
            [str(MODULE.RUNTIME_LAUNCHER), "-I", "-S", "-c", probe],
            cwd=ROOT,
            env={"HOME": "/var/root", "TMPDIR": "/private/tmp"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, r"runpy|-c|-m|rewritten argv")

    def test_production_reauthentication_uses_held_candidate_descriptor(self) -> None:
        source = TOOL.read_text(encoding="ascii")
        self.assertIn('"WINS_CANDIDATE_RECEIPT_FD": str(receipt_fd)', source)
        self.assertIn("pass_fds=(source_fd, receipt_fd, *dependencies.pass_fds())", source)
        self.assertIn('"WINS_HELD_DEPENDENCIES_JSON"', source)
        self.assertIn('f"/dev/fd/{probe_fd}"', source)
        self.assertIn("pass_fds=(probe_fd,)", source)
        self.assertNotIn("pass_fds=(dependencies.package.fd,)", source)
        self.assertIn(
            "with _held_package_probe_descriptor(dependencies.package) as probe_fd:",
            source,
        )
        self.assertIn("@contextmanager\ndef _held_package_probe_descriptor", source)
        self.assertIn("dir_fd=package.directory.fd", source)
        self.assertIn('"/usr/sbin/pkgutil",', source)
        self.assertIn('receipt=namespace["parse_receipt"](rdata)', source)
        self.assertNotIn('namespace["parse_receipt"](receipt_path.read_bytes())', source)
        self.assertIn("forbidden_writable_uid=owner_uid", source)
        self.assertIn("dependencies.validate()", source)
        self.assertGreaterEqual(source.count("forbid_descendants=True"), 2)
        self.assertEqual(source.count("forbid_descendants=False"), 1)
        self.assertIn("_validate_reauthentication_exec_surface(source_data)", source)
        self.assertLess(
            source.index("_validate_reauthentication_exec_surface(source_data)"),
            source.index("bootstrap = r'''"),
        )
        self.assertIn('source_fd = os.open(\n        source_path,\n        os.O_RDONLY', source)
        self.assertIn('data=b"".join(iter(lambda:os.read(fd,1048576),b""))', source)
        self.assertIn("assert sys.flags.isolated==1 and sys.flags.no_site==1", source)
        self.assertIn('exec(compile(data,path,"exec"),namespace,namespace)', source)
        self.assertIn(
            "pass_fds=(source_fd, receipt_fd, *dependencies.pass_fds())", source
        )
        self.assertIn('"WINS_CODESIGN_INVOCATION_LIMIT"', source)
        self.assertIn('namespace["_codesign_invocation_count"]', source)
        self.assertIn("_run_bounded_child(", source)
        self.assertIn("selectors.DefaultSelector()", source)
        self.assertIn("select_timeout = min(remaining, 0.05)", source)
        self.assertNotIn("select_timeout = remaining\n", source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", source)
        self.assertNotIn("process.communicate(", source)
        self.assertLess(
            source.index('records=json.loads(os.environ["WINS_HELD_DEPENDENCIES_JSON"])'),
            source.index('if os.environ["WINS_REAUTH_MODE"]=="published"'),
        )
        self.assertLess(source.index('"/usr/sbin/pkgutil",'), source.index("bootstrap,"))

    def test_production_cli_refuses_repo_path_and_nonroot_apply(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(TOOL), "recover"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(
            completed.stderr,
            r"runpy, -c, -m, or rewritten argv|native launcher bootstrap runtime descriptor",
        )

    def test_import_forgery_cannot_create_native_parent_capability(self) -> None:
        probe = (
            "import importlib.util,os,pathlib,sys;"
            f"p=pathlib.Path({str(TOOL)!r});"
            "s=importlib.util.spec_from_file_location('forged_owner',p);"
            "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "m.__name__='__main__';m.__spec__=None;m.__package__=None;"
            f"m.__file__={str(MODULE.OWNER_PROVISION_PATH)!r};"
            f"sys.argv=[{str(MODULE.OWNER_PROVISION_PATH)!r},'recover'];"
            f"os.environ['WINS_OWNER_CAPABILITY_FD']={str(MODULE.NATIVE_CAPABILITY_FD)!r};"
            f"os.environ['WINS_OWNER_CONTROLLER_FD']={str(MODULE.NATIVE_CONTROLLER_FD)!r};"
            "raise SystemExit(m.main())"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-c", probe],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(
            completed.stderr,
            r"native launcher bootstrap|refuses runpy, -c, -m",
        )

    def test_installer_is_syntax_clean_and_does_not_self_elevate_or_migrate(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-n", str(INSTALLER)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        source = INSTALLER.read_text(encoding="ascii")
        lowered = source.lower()
        self.assertNotIn("sudo ", lowered)
        self.assertNotIn("curl ", lowered)
        self.assertNotIn("wget ", lowered)
        self.assertNotIn("authority.json", source)
        self.assertNotIn("receipt.json", source)
        self.assertNotIn("noschg", source)
        self.assertNotIn("SUDO_UID", source)
        self.assertNotIn("SUDO_GID", source)
        self.assertIn("root must never interpret", lowered)
        self.assertIn("owner-installer-bootstrap", source)
        self.assertIn("root must invoke only the fixed native bootstrap", source)
        self.assertNotRegex(
            source,
            r"(?m)^\s*(?:/bin/)?(?:cp|mv|mkdir|chmod|chown|chflags|install)\b",
        )
        self.assertIn("REVIEWED_CONTROLLER_SHA256", source)
        self.assertIn("REVIEWED_LAUNCHER_SHA256", source)
        self.assertIn(str(MODULE.OWNER_PROVISION_PATH), source)
        self.assertIn(str(MODULE.OWNER_LAUNCHER_PATH), source)

    def test_installer_nonroot_run_changes_no_library_state(self) -> None:
        before = MODULE.OWNER_PROVISION_PATH.exists()
        completed = subprocess.run(
            [
                "/bin/bash",
                str(INSTALLER),
                hashlib.sha256(INSTALLER.read_bytes()).hexdigest(),
                hashlib.sha256(TOOL.read_bytes()).hexdigest(),
                str(TOOL),
                hashlib.sha256(TOOL.read_bytes()).hexdigest(),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(MODULE.OWNER_PROVISION_PATH.exists(), before)


if __name__ == "__main__":
    unittest.main()
