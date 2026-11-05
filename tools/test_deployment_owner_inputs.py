#!/usr/bin/env python3
"""Adversarial tests for deployment_owner_inputs.py."""

from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "tools/deployment_owner_inputs.py"
SPEC = importlib.util.spec_from_file_location("deployment_owner_inputs", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class DeploymentOwnerInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = tool.strict_json_load(tool.SCHEMA_PATH, "schema")
        self.template = tool.strict_json_load(tool.TEMPLATE_PATH, "template")
        self.template_bytes = tool.TEMPLATE_PATH.read_bytes()
        self.schema_bytes = tool.SCHEMA_PATH.read_bytes()
        self.collector_bytes = tool.COLLECTOR_PATH.read_bytes()

    @staticmethod
    def _ancestors_are_safe(directory: Path) -> bool:
        # The collector's own ancestor rule (_open_parent): every directory
        # above an input is owned by root or by us and is not group- or
        # other-writable. Linux /tmp (1777) fails it; the per-user macOS
        # temporary directory passes.
        for ancestor in (directory, *directory.parents):
            info = ancestor.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, os.geteuid()}
                or info.st_mode & 0o022
            ):
                return False
        return True

    def _safe_root(self) -> Path:
        # macOS exposes /var as a symlink to /private/var. The collector
        # deliberately refuses symlink ancestors, so tests use the canonical
        # path returned after resolving that platform alias. The fixture root
        # must sit below ancestors the collector accepts, or every case fails
        # on the ancestor rule before reaching what it tests.
        bases = [Path(tempfile.gettempdir()).resolve(), Path.home().resolve()]
        base = next((candidate for candidate in bases if self._ancestors_are_safe(candidate)), None)
        if base is None:
            self.fail(f"no fixture base with collector-safe ancestors among {bases}")
        root = Path(tempfile.mkdtemp(prefix="wins-owner-inputs-", dir=base)).resolve()
        os.chmod(root, 0o700)
        self.addCleanup(self._cleanup, root)
        return root

    @staticmethod
    def _cleanup(root: Path) -> None:
        if not root.exists():
            return
        for current, directories, files in os.walk(root, topdown=False, followlinks=False):
            for name in files:
                path = Path(current) / name
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            for name in directories:
                path = Path(current) / name
                if path.is_symlink():
                    path.unlink()
                else:
                    path.rmdir()
        root.rmdir()

    def _bindings(self, entries=None):
        return {
            "schema_version": 1,
            "contract": tool.BINDINGS_CONTRACT,
            "claimed_approved_sha": None,
            "items": entries or [],
        }

    def test_pending_manifest_and_schema_are_in_lockstep(self) -> None:
        tool.validate_schema_contract(self.schema)
        record = tool.validate_manifest(self.template, allow_verified=False)
        self.assertEqual(record["status"], tool.PENDING)
        self.assertFalse(record["deployment_authorized"])
        self.assertTrue(all(item["status"] == tool.PENDING for item in record["items"]))
        item_schema = self.schema["properties"]["items"]["items"]
        self.assertEqual(set(self.schema["required"]), tool.TOP_LEVEL_KEYS)
        self.assertEqual(set(item_schema["required"]), tool.ITEM_KEYS)

    def test_schema_unknown_keyword_fails_closed(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["unevaluatedProperties"] = False
        with self.assertRaisesRegex(tool.EvidenceError, "unsupported schema keywords"):
            tool.validate_schema_contract(schema)

    def test_schema_unresolved_reference_fails_closed(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["properties"]["status"] = {"$ref": "#/$defs/not-present"}
        with self.assertRaisesRegex(tool.EvidenceError, "unresolved"):
            tool.validate_schema_contract(schema)

    def test_duplicate_json_key_is_rejected(self) -> None:
        root = self._safe_root()
        duplicate = root / "duplicate.json"
        duplicate.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
        os.chmod(duplicate, 0o600)
        with self.assertRaisesRegex(tool.EvidenceError, "duplicate JSON key"):
            tool.strict_json_load(duplicate, "duplicate", secure=True)

    def test_pending_manifest_cannot_force_authorization(self) -> None:
        record = copy.deepcopy(self.template)
        record["deployment_authorized"] = True
        with self.assertRaisesRegex(tool.EvidenceError, "authorization"):
            tool.validate_manifest(record, allow_verified=False)

    def test_collector_refuses_verified_input_item(self) -> None:
        record = copy.deepcopy(self.template)
        record["items"][0]["status"] = tool.VERIFIED
        record["items"][0]["evidence"] = {
            "path": "/owner/evidence.json",
            "kind": "file",
            "sha256": "1" * 64,
            "size_bytes": 1,
            "mode": "0600",
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "captured_at_utc": "2026-09-02T00:00:00Z",
            "member_count": 0,
        }
        record["items"][0]["missing_reason"] = None
        with self.assertRaisesRegex(tool.EvidenceError, "claims VERIFIED"):
            tool.validate_manifest(record, allow_verified=False)

    def test_secure_file_read_and_exact_digest(self) -> None:
        root = self._safe_root()
        source = root / "evidence.bin"
        source.write_bytes(b"exact evidence bytes\n")
        os.chmod(source, 0o600)
        record = tool.collect_path(source, "file", owner_only=True)
        self.assertEqual(record["sha256"], tool.sha256_bytes(b"exact evidence bytes\n"))
        self.assertEqual(record["mode"], "0600")
        self.assertEqual(record["member_count"], 0)

    def test_symlink_leaf_is_rejected(self) -> None:
        root = self._safe_root()
        source = root / "source"
        source.write_bytes(b"evidence")
        os.chmod(source, 0o600)
        link = root / "link"
        link.symlink_to(source)
        with self.assertRaises((tool.EvidenceError, OSError)):
            tool.collect_path(link, "file", owner_only=True)

    def test_symlink_ancestor_is_rejected(self) -> None:
        root = self._safe_root()
        real = root / "real"
        real.mkdir(mode=0o700)
        source = real / "source"
        source.write_bytes(b"evidence")
        os.chmod(source, 0o600)
        link = root / "linked"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises((tool.EvidenceError, OSError)):
            tool.collect_path(link / "source", "file", owner_only=True)

    def test_world_writable_ancestor_is_rejected(self) -> None:
        root = self._safe_root()
        unsafe = root / "unsafe"
        unsafe.mkdir(mode=0o700)
        os.chmod(unsafe, 0o777)
        source = unsafe / "source"
        source.write_bytes(b"evidence")
        os.chmod(source, 0o600)
        with self.assertRaisesRegex(tool.EvidenceError, "ancestor"):
            tool.collect_path(source, "file", owner_only=True)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires os.mkfifo")
    def test_fifo_is_rejected_without_opening(self) -> None:
        root = self._safe_root()
        fifo = root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(tool.EvidenceError, "special file"):
            tool.collect_path(fifo, "file", owner_only=True)

    def test_extra_hard_link_is_rejected(self) -> None:
        root = self._safe_root()
        source = root / "source"
        source.write_bytes(b"secret evidence")
        os.chmod(source, 0o600)
        os.link(source, root / "other")
        with self.assertRaisesRegex(tool.EvidenceError, "one-link"):
            tool.collect_path(source, "file", owner_only=True)

    def test_file_identity_change_is_rejected(self) -> None:
        root = self._safe_root()
        source = root / "source"
        source.write_bytes(b"evidence")
        os.chmod(source, 0o600)
        original_identity = tool._identity
        calls = {"count": 0}

        def changing_identity(info):
            calls["count"] += 1
            value = original_identity(info)
            if calls["count"] >= 2:
                return value[:-1] + (value[-1] + 1,)
            return value

        with mock.patch.object(tool, "_identity", side_effect=changing_identity):
            with self.assertRaisesRegex(tool.EvidenceError, "changed during collection"):
                tool.collect_path(source, "file", owner_only=True)

    def test_directory_digest_is_deterministic_and_rejects_symlinks(self) -> None:
        root = self._safe_root()
        directory = root / "material"
        directory.mkdir(mode=0o700)
        first = directory / "a"
        second = directory / "b"
        first.write_bytes(b"one")
        second.write_bytes(b"two")
        os.chmod(first, 0o600)
        os.chmod(second, 0o600)
        before = tool.collect_path(directory, "directory", owner_only=True)
        after = tool.collect_path(directory, "directory", owner_only=True)
        self.assertEqual(before["sha256"], after["sha256"])
        self.assertEqual(before["member_count"], 2)
        empty = directory / "empty"
        empty.mkdir(mode=0o700)
        with_empty = tool.collect_path(directory, "directory", owner_only=True)
        self.assertNotEqual(before["sha256"], with_empty["sha256"])
        self.assertEqual(with_empty["member_count"], 3)
        (directory / "link").symlink_to(first)
        with self.assertRaisesRegex(tool.EvidenceError, "symlink or special"):
            tool.collect_path(directory, "directory", owner_only=True)

    def test_expected_digest_mismatch_is_conflict_and_never_authorized(self) -> None:
        root = self._safe_root()
        source = root / "audit.json"
        source.write_bytes(b"auditor bytes")
        os.chmod(source, 0o600)
        bindings = self._bindings([
            {
                "id": "shared.final-audit-go",
                "path": str(source),
                "expected_sha256": "0" * 64,
            }
        ])
        tool.validate_bindings(bindings, (item["id"] for item in self.template["items"]))
        with mock.patch.object(tool, "_producer_record", return_value={
            "collector_path": "tools/deployment_owner_inputs.py",
            "collector_sha256": "1" * 64,
            "schema_path": "tools/deployment_owner_inputs.schema.json",
            "schema_sha256": "2" * 64,
            "template_path": "deploy/production-input-evidence/PENDING-OWNER-INPUT.json",
            "template_sha256": tool.sha256_bytes(self.template_bytes),
            "collector_closure_sha256": "4" * 64,
            "repository_head": "5" * 64,
            "repository_clean": True,
        }):
            evidence = tool.build_evidence(
                self.template,
                bindings,
                self.template_bytes,
                self.schema_bytes,
                self.collector_bytes,
            )
        selected = next(item for item in evidence["items"] if item["id"] == "shared.final-audit-go")
        self.assertEqual(selected["status"], tool.CONFLICT)
        self.assertEqual(evidence["status"], tool.CONFLICT)
        self.assertFalse(evidence["deployment_authorized"])

    def test_claimed_40_hex_sha_is_checked_but_not_laundered(self) -> None:
        head = "5" * 40
        bindings = self._bindings()
        bindings["claimed_approved_sha"] = head
        with mock.patch.object(tool, "_producer_record", return_value={
            "collector_path": "tools/deployment_owner_inputs.py",
            "collector_sha256": "1" * 64,
            "schema_path": "tools/deployment_owner_inputs.schema.json",
            "schema_sha256": "2" * 64,
            "template_path": "deploy/production-input-evidence/PENDING-OWNER-INPUT.json",
            "template_sha256": tool.sha256_bytes(self.template_bytes),
            "collector_closure_sha256": "4" * 64,
            "repository_head": head,
            "repository_clean": True,
        }):
            evidence = tool.build_evidence(
                self.template,
                bindings,
                self.template_bytes,
                self.schema_bytes,
                self.collector_bytes,
            )
        self.assertIsNone(evidence["approved_sha"])
        self.assertFalse(evidence["deployment_authorized"])

    def test_claimed_sha_must_equal_collecting_head(self) -> None:
        bindings = self._bindings()
        bindings["claimed_approved_sha"] = "5" * 40
        with mock.patch.object(tool, "_producer_record", return_value={
            "collector_path": "tools/deployment_owner_inputs.py",
            "collector_sha256": "1" * 64,
            "schema_path": "tools/deployment_owner_inputs.schema.json",
            "schema_sha256": "2" * 64,
            "template_path": "deploy/production-input-evidence/PENDING-OWNER-INPUT.json",
            "template_sha256": tool.sha256_bytes(self.template_bytes),
            "collector_closure_sha256": "4" * 64,
            "repository_head": "6" * 40,
            "repository_clean": True,
        }):
            with self.assertRaisesRegex(tool.EvidenceError, "does not match"):
                tool.build_evidence(
                    self.template,
                    bindings,
                    self.template_bytes,
                    self.schema_bytes,
                    self.collector_bytes,
                )

    def test_dependency_cycle_is_rejected(self) -> None:
        record = copy.deepcopy(self.template)
        record["items"][0]["depends_on"].append(record["items"][0]["id"])
        with self.assertRaisesRegex(tool.EvidenceError, "cycle"):
            tool.validate_manifest(record, allow_verified=False)

    def test_later_stage_dependency_is_rejected(self) -> None:
        record = copy.deepcopy(self.template)
        early = next(item for item in record["items"] if item["stage"] == "stage-0")
        late = next(item for item in record["items"] if item["stage"] == "stage-1")
        early["depends_on"].append(late["id"])
        with self.assertRaisesRegex(tool.EvidenceError, "later deployment stage"):
            tool.validate_manifest(record, allow_verified=False)

    def test_orphan_observation_is_rejected(self) -> None:
        record = copy.deepcopy(self.template)
        record["workstation_observations"][0]["relates_to"] = "unknown.item"
        with self.assertRaisesRegex(tool.EvidenceError, "unknown item"):
            tool.validate_manifest(record, allow_verified=False)

    def test_unpinned_source_reference_is_rejected(self) -> None:
        record = copy.deepcopy(self.template)
        record["items"][0]["source_refs"][0]["path"] = "/not/a/pinned/source"
        with self.assertRaisesRegex(tool.EvidenceError, "not pinned"):
            tool.validate_manifest(record, allow_verified=False)

    def test_dropped_inventory_item_is_rejected(self) -> None:
        record = copy.deepcopy(self.template)
        record["items"].pop()
        with self.assertRaisesRegex(tool.EvidenceError, "item IDs differ"):
            tool.validate_manifest(
                record,
                allow_verified=False,
                expected_template=self.template,
                expected_template_sha256=tool.sha256_bytes(self.template_bytes),
            )

    def test_required_flag_downgrade_is_rejected(self) -> None:
        record = copy.deepcopy(self.template)
        record["items"][0]["required"] = False
        with self.assertRaisesRegex(tool.EvidenceError, "required differs"):
            tool.validate_manifest(
                record,
                allow_verified=False,
                expected_template=self.template,
                expected_template_sha256=tool.sha256_bytes(self.template_bytes),
            )

    def test_authorized_record_requires_readable_exact_attestation(self) -> None:
        record = copy.deepcopy(self.template)
        approved = "a" * 40
        for item in record["items"]:
            item["status"] = tool.VERIFIED
            item["missing_reason"] = None
            item["evidence"] = {
                "path": "/owner/evidence/{}.json".format(item["id"]),
                "kind": "file",
                "sha256": "b" * 64,
                "size_bytes": 1,
                "mode": "0600",
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "captured_at_utc": "2026-09-02T00:00:00Z",
                "member_count": 0,
            }
        record["status"] = tool.VERIFIED
        record["deployment_authorized"] = True
        record["approved_sha"] = approved
        record["producer"] = {
            "collector_path": "tools/deployment_owner_inputs.py",
            "collector_sha256": "1" * 64,
            "schema_path": "tools/deployment_owner_inputs.schema.json",
            "schema_sha256": "2" * 64,
            "template_path": "deploy/production-input-evidence/PENDING-OWNER-INPUT.json",
            "template_sha256": "3" * 64,
            "collector_closure_sha256": "4" * 64,
            "repository_head": approved,
            "repository_clean": True,
        }
        record["authorization"] = {
            "method": "external-auditor-attestation",
            "approved_sha": approved,
            "attestation_path": "/definitely/not/present/winsvpn-attestation.json",
            "attestation_sha256": "c" * 64,
            "signer": "external-auditor",
            "signed_at_utc": "2026-09-02T00:00:00Z",
        }
        with self.assertRaisesRegex(tool.EvidenceError, "securely read evidence input"):
            tool.validate_manifest(record, allow_verified=True)

    def test_output_directory_reuse_is_rejected(self) -> None:
        root = self._safe_root()
        output = root / "evidence"
        output.mkdir(mode=0o700)
        with self.assertRaisesRegex(tool.EvidenceError, "already exists"):
            tool.write_evidence_directory(output, self.template)

    def test_bindings_accept_paths_only_and_reject_unknown_fields(self) -> None:
        bindings = self._bindings([
            {
                "id": "shared.final-audit-go",
                "path": None,
                "expected_sha256": None,
                "secret_value": "forbidden",
            }
        ])
        with self.assertRaisesRegex(tool.EvidenceError, "keys mismatch"):
            tool.validate_bindings(bindings, (item["id"] for item in self.template["items"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
