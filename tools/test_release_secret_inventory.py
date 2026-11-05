#!/usr/bin/env python3
"""Fail-closed regressions for the local exact known-server-secret inventory."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import release_secret_inventory as inventory


SYNTHETIC_ALPHA = "synthetic-inventory-secret-alpha-0001"
SYNTHETIC_BETA = "synthetic-inventory-secret-beta-0002"
SYNTHETIC_SHARED = "synthetic-inventory-secret-shared-0003"


def _fragments(*values: str) -> tuple[str, ...]:
    fragments: list[str] = []
    for value in values:
        fragments.append(value)
        fragments.append(hashlib.sha256(value.encode("utf-8")).hexdigest())
    return tuple(fragments)


def _write_inventory(
    path: pathlib.Path,
    *,
    revision: str = "rev-test-1",
    secrets: dict[str, str] | None = None,
    mode: int = 0o600,
    raw: str | None = None,
) -> pathlib.Path:
    if raw is None:
        payload = {
            "schema_version": 1,
            "revision": revision,
            "secrets": secrets
            or {
                "SYNTHETIC_ALPHA": SYNTHETIC_ALPHA,
            },
        }
        path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    else:
        path.write_bytes(raw.encode("utf-8"))
    path.chmod(mode)
    return path


def _assert_undisclosed(test: unittest.TestCase, text: str, *values: str) -> None:
    for fragment in _fragments(*values):
        test.assertNotIn(fragment, text)


def _churn_tempdir_siblings(tag: str) -> None:
    root = pathlib.Path(tempfile.gettempdir())
    sibling = root / f"wins-relpriv-churn-{os.getpid()}-{tag}-{time.time_ns()}"
    sibling.mkdir()
    try:
        (sibling / "nlink").mkdir()
        try:
            os.utime(root, None)
        except OSError:
            pass
    finally:
        shutil.rmtree(sibling, ignore_errors=True)


def _churn_bound_ancestors(path: pathlib.Path, index: int) -> None:
    _churn_tempdir_siblings(f"{path.name}-{index}")
    parent = path.parent
    local = parent / f"wins-local-churn-{index}-{time.time_ns()}"
    local.mkdir()
    try:
        (local / "nlink").mkdir()
    finally:
        shutil.rmtree(local, ignore_errors=True)
    bound = pathlib.Path(*path.parts[: index + 1])
    try:
        os.utime(bound, None)
    except OSError:
        pass


class ReleaseSecretInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="wins-secret-inventory-")
        self.base = pathlib.Path(self._temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.external = self.base / "external"
        self.external.mkdir()

    def tearDown(self) -> None:
        self._temp.cleanup()

    def load(self, path: pathlib.Path, repository_root: pathlib.Path | None = None):
        return inventory.load_secret_inventory(
            path, repository_root=repository_root or ROOT
        )

    def test_valid_external_inventory_streams_values_and_redacts_summaries(self) -> None:
        path = _write_inventory(
            self.external / "inventory.json",
            secrets={
                "SYNTHETIC_BETA": SYNTHETIC_BETA,
                "SYNTHETIC_ALPHA": SYNTHETIC_ALPHA,
            },
        )
        loaded = self.load(path)
        self.assertEqual(loaded.revision, "rev-test-1")
        self.assertEqual(loaded.labels, ("SYNTHETIC_ALPHA", "SYNTHETIC_BETA"))
        self.assertEqual(loaded.label_count, 2)
        self.assertEqual(loaded.unique_value_count, 2)
        with self.assertRaisesRegex(
            inventory.InventoryError, "direct secret streaming is not release coverage"
        ):
            list(loaded.stream_secret_values())
        streamed = list(loaded._stream_secret_values())
        self.assertEqual(
            streamed,
            [
                ("SYNTHETIC_ALPHA", SYNTHETIC_ALPHA),
                ("SYNTHETIC_BETA", SYNTHETIC_BETA),
            ],
        )
        summary = json.dumps(loaded.public_summary())
        rendered = repr(loaded)
        _assert_undisclosed(self, summary, SYNTHETIC_ALPHA, SYNTHETIC_BETA)
        _assert_undisclosed(self, rendered, SYNTHETIC_ALPHA, SYNTHETIC_BETA)
        self.assertEqual(
            loaded.public_summary(),
            {
                "revision": "rev-test-1",
                "labels": ["SYNTHETIC_ALPHA", "SYNTHETIC_BETA"],
                "label_count": 2,
                "unique_value_count": 2,
                "authenticated": False,
                "durable_secret_custody": "server-side",
            },
        )

    def test_duplicate_values_count_once_and_stay_out_of_output(self) -> None:
        path = _write_inventory(
            self.external / "duplicate-values.json",
            secrets={
                "SYNTHETIC_ALPHA": SYNTHETIC_SHARED,
                "SYNTHETIC_BETA": SYNTHETIC_SHARED,
            },
        )
        loaded = self.load(path)
        self.assertEqual(loaded.label_count, 2)
        self.assertEqual(loaded.unique_value_count, 1)
        _assert_undisclosed(self, repr(loaded), SYNTHETIC_SHARED)
        _assert_undisclosed(self, json.dumps(loaded.public_summary()), SYNTHETIC_SHARED)

    def test_relative_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "explicit absolute path"):
            self.load(pathlib.Path("inventory.json"))

    def test_dotdot_path_is_rejected(self) -> None:
        path = _write_inventory(self.external / "inventory.json")
        sneaky = self.external / "nested"
        sneaky.mkdir()
        with self.assertRaisesRegex(inventory.InventoryError, "explicit absolute path"):
            self.load(sneaky / ".." / "inventory.json")

    def test_repository_path_is_rejected(self) -> None:
        path = _write_inventory(self.repo / "inventory.json")
        with self.assertRaisesRegex(inventory.InventoryError, "external path"):
            self.load(path, repository_root=self.repo)

    def test_wrong_mode_is_rejected(self) -> None:
        for mode in (0o644, 0o666, 0o700, 0o640):
            with self.subTest(mode=oct(mode)):
                path = _write_inventory(self.external / f"mode-{mode:o}.json", mode=mode)
                with self.assertRaisesRegex(
                    inventory.InventoryError, "mode 0600 or stricter"
                ):
                    self.load(path)

    def test_owner_only_read_mode_is_accepted(self) -> None:
        path = _write_inventory(self.external / "strict.json", mode=0o400)
        loaded = self.load(path)
        self.assertEqual(loaded.label_count, 1)

    def test_wrong_owner_simulation_is_rejected(self) -> None:
        path = _write_inventory(self.external / "owner.json")
        with mock.patch.object(inventory.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(inventory.InventoryError, "current user"):
                self.load(path)

    def test_symlink_is_rejected(self) -> None:
        real = _write_inventory(self.external / "real.json")
        linked = self.external / "linked.json"
        linked.symlink_to(real)
        self.assertTrue(linked.is_symlink())
        with self.assertRaisesRegex(inventory.InventoryError, "non-symlink"):
            self.load(linked)

    def test_hardlink_is_rejected(self) -> None:
        real = _write_inventory(self.external / "real-hardlink.json")
        alias = self.external / "alias.json"
        os.link(real, alias)
        self.assertEqual(real.stat().st_nlink, 2)
        with self.assertRaisesRegex(inventory.InventoryError, "link count 1"):
            self.load(alias)
        with self.assertRaisesRegex(inventory.InventoryError, "link count 1"):
            self.load(real)

    def test_oversized_inventory_is_rejected_before_json_parsing(self) -> None:
        path = self.external / "oversized.json"
        path.write_bytes(b"{" + (b" " * inventory.MAX_INVENTORY_BYTES))
        path.chmod(0o600)
        with self.assertRaisesRegex(inventory.InventoryError, "size is outside"):
            self.load(path)

    def test_duplicate_top_level_and_secret_keys_are_rejected(self) -> None:
        top = (
            '{"schema_version":1,"schema_version":1,"revision":"rev-test-1",'
            '"secrets":{"SYNTHETIC_ALPHA":"' + SYNTHETIC_ALPHA + '"}}'
        )
        nested = (
            '{"schema_version":1,"revision":"rev-test-1","secrets":'
            '{"SYNTHETIC_ALPHA":"' + SYNTHETIC_ALPHA + '",'
            '"SYNTHETIC_ALPHA":"' + SYNTHETIC_BETA + '"}}'
        )
        for raw, name in ((top, "top.json"), (nested, "nested.json")):
            with self.subTest(name=name):
                path = _write_inventory(self.external / name, raw=raw)
                with self.assertRaisesRegex(inventory.InventoryError, "duplicate JSON key"):
                    self.load(path)

    def test_missing_and_wrong_schema_are_rejected(self) -> None:
        cases = (
            (
                '{"revision":"rev-test-1","secrets":{"SYNTHETIC_ALPHA":"'
                + SYNTHETIC_ALPHA
                + '"}}',
                "not exact",
            ),
            (
                '{"schema_version":2,"revision":"rev-test-1","secrets":{"SYNTHETIC_ALPHA":"'
                + SYNTHETIC_ALPHA
                + '"}}',
                "schema_version",
            ),
            (
                '{"schema_version":true,"revision":"rev-test-1","secrets":{"SYNTHETIC_ALPHA":"'
                + SYNTHETIC_ALPHA
                + '"}}',
                "schema_version",
            ),
            (
                '{"schema_version":1,"revision":"rev-test-1","secrets":{"SYNTHETIC_ALPHA":"'
                + SYNTHETIC_ALPHA
                + '"},"comment":"no"}',
                "not exact",
            ),
            (
                '{"schema_version":1,"revision":"rev-test-1","secrets":{}}',
                "at least one label",
            ),
            (
                '{"schema_version":1,"revision":"rev-test-1","secrets":[]}',
                "secrets must be one JSON object",
            ),
            ("[]", "JSON object"),
        )
        for raw, pattern in cases:
            with self.subTest(pattern=pattern):
                path = _write_inventory(self.external / "schema.json", raw=raw)
                with self.assertRaisesRegex(inventory.InventoryError, pattern):
                    self.load(path)

    def test_transcript_json_is_rejected(self) -> None:
        transcripts = (
            '{"messages":[{"role":"user","content":"synthetic"}]}',
            '{"schema_version":1,"revision":"rev-test-1","secrets":{"SYNTHETIC_ALPHA":"'
            + SYNTHETIC_ALPHA
            + '"},"messages":[]}',
            '{"role":"assistant","content":"synthetic-transcript"}',
            '{"transcript":"synthetic","conversation":[]}',
        )
        for index, raw in enumerate(transcripts):
            with self.subTest(index=index):
                path = _write_inventory(self.external / f"transcript-{index}.json", raw=raw)
                with self.assertRaisesRegex(
                    inventory.InventoryError, "transcript/message schema"
                ):
                    self.load(path)

    def test_invalid_labels_values_and_revision_are_rejected(self) -> None:
        cases = (
            (
                {
                    "schema_version": 1,
                    "revision": "rev-test-1",
                    "secrets": {"bad-label": SYNTHETIC_ALPHA},
                },
                "invalid ASCII label",
            ),
            (
                {
                    "schema_version": 1,
                    "revision": "rev-test-1",
                    "secrets": {"AB": SYNTHETIC_ALPHA},
                },
                "invalid ASCII label",
            ),
            (
                {
                    "schema_version": 1,
                    "revision": "rev-test-1",
                    "secrets": {"SYNTHETIC_ALPHA": ""},
                },
                "nonempty strings",
            ),
            (
                {
                    "schema_version": 1,
                    "revision": "rev-test-1",
                    "secrets": {"SYNTHETIC_ALPHA": "short"},
                },
                "outside the accepted bound",
            ),
            (
                {
                    "schema_version": 1,
                    "revision": "rev-test-1",
                    "secrets": {"SYNTHETIC_ALPHA": "x" * (inventory.MAX_VALUE_CHARS + 1)},
                },
                "outside the accepted bound",
            ),
            (
                {
                    "schema_version": 1,
                    "revision": "",
                    "secrets": {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
                },
                "revision",
            ),
            (
                {
                    "schema_version": 1,
                    "revision": "rev\n1",
                    "secrets": {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
                },
                "revision",
            ),
        )
        for payload, pattern in cases:
            with self.subTest(pattern=pattern):
                path = self.external / "invalid.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                path.chmod(0o600)
                with self.assertRaisesRegex(inventory.InventoryError, pattern):
                    self.load(path)
                error = None
                try:
                    self.load(path)
                except inventory.InventoryError as exc:
                    error = str(exc)
                self.assertIsNotNone(error)
                _assert_undisclosed(self, error or "", SYNTHETIC_ALPHA)

    def test_load_errors_do_not_echo_secret_values(self) -> None:
        path = _write_inventory(self.external / "mode.json", mode=0o644)
        with self.assertRaises(inventory.InventoryError) as raised:
            self.load(path)
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)

    def test_nested_duplicate_keys_are_rejected_recursively(self) -> None:
        raw = (
            '{"schema_version":1,"revision":"rev-test-1","secrets":'
            '{"SYNTHETIC_ALPHA":"' + SYNTHETIC_ALPHA + '",'
            '"WRAP":{"inner":1,"inner":2}}}'
        )
        path = _write_inventory(self.external / "nested-dup.json", raw=raw)
        with self.assertRaisesRegex(inventory.InventoryError, "duplicate JSON key"):
            self.load(path)

    def test_nested_transcript_and_export_shapes_are_rejected(self) -> None:
        nested_transcript = (
            '{"schema_version":1,"revision":"rev-test-1","secrets":'
            '{"SYNTHETIC_ALPHA":{"role":"user","content":"' + SYNTHETIC_ALPHA + '"}}}'
        )
        nested_export = (
            '{"schema_version":1,"revision":"rev-test-1","secrets":'
            '{"SYNTHETIC_ALPHA":"' + SYNTHETIC_ALPHA + '",'
            '"WRAP":{"export":{"messages":[]}}}}'
        )
        for index, raw in enumerate((nested_transcript, nested_export)):
            with self.subTest(index=index):
                path = _write_inventory(self.external / f"nested-shape-{index}.json", raw=raw)
                with self.assertRaisesRegex(
                    inventory.InventoryError, "transcript/message schema"
                ):
                    self.load(path)

    def test_revision_and_labels_must_not_equal_or_contain_secrets_or_hashes(self) -> None:
        digest = hashlib.sha256(SYNTHETIC_ALPHA.encode("utf-8")).hexdigest()
        path = self.external / "public-fields.json"
        payload = {
            "schema_version": 1,
            "revision": SYNTHETIC_ALPHA,
            "secrets": {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaisesRegex(inventory.InventoryError, "public fields"):
            self.load(path)
        error = ""
        try:
            self.load(path)
        except inventory.InventoryError as exc:
            error = str(exc)
        _assert_undisclosed(self, error, SYNTHETIC_ALPHA)

        payload["revision"] = "rev-" + digest
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaisesRegex(inventory.InventoryError, "public fields"):
            self.load(path)
        error = ""
        try:
            self.load(path)
        except inventory.InventoryError as exc:
            error = str(exc)
        _assert_undisclosed(self, error, SYNTHETIC_ALPHA)
        self.assertNotIn(digest, error)

    def test_parser_exceptions_are_not_retained_as_causes(self) -> None:
        raw = '{"schema_version":1,"revision":"rev-test-1","secrets":{"SYNTHETIC_ALPHA":"'
        raw += SYNTHETIC_ALPHA + '"'
        path = _write_inventory(self.external / "truncated.json", raw=raw)
        with self.assertRaises(inventory.InventoryError) as raised:
            self.load(path)
        self.assertIsNone(raised.exception.__cause__)
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)
        _assert_undisclosed(self, repr(raised.exception), SYNTHETIC_ALPHA)

        invalid_utf = self.external / "binary.json"
        invalid_utf.write_bytes(b"\xff\xfe" + SYNTHETIC_ALPHA.encode("utf-8"))
        invalid_utf.chmod(0o600)
        with self.assertRaises(inventory.InventoryError) as raised:
            self.load(invalid_utf)
        self.assertIsNone(raised.exception.__cause__)
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)

    def test_initial_lstat_is_bound_to_opened_descriptor_and_replacement_is_rejected(
        self,
    ) -> None:
        good = _write_inventory(
            self.external / "good.json",
            secrets={"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
        )
        evil = _write_inventory(
            self.external / "evil.json",
            secrets={"SYNTHETIC_BETA": SYNTHETIC_BETA},
        )
        artifact_name = good.name
        real_open = os.open
        real_openat = getattr(os, "openat", None)

        def swapping_open(path, flags, *args, **kwargs):
            if os.path.basename(os.fspath(path)) == artifact_name:
                os.replace(evil, good)
                os.chmod(good, 0o600)
            return real_open(path, flags, *args, **kwargs)

        def swapping_openat(dir_fd, name, flags, *args, **kwargs):
            if name == artifact_name:
                os.replace(evil, good)
                os.chmod(good, 0o600)
            return real_openat(dir_fd, name, flags, *args, **kwargs)

        patches = [mock.patch.object(inventory.os, "open", swapping_open)]
        if real_openat is not None:
            patches.append(mock.patch.object(inventory.os, "openat", swapping_openat))
        with contextlib.ExitStack() as stack:
            for patched in patches:
                stack.enter_context(patched)
            with self.assertRaisesRegex(inventory.InventoryError, "replaced"):
                self.load(good)

    def test_authenticated_contract_rejects_decoy_label_omission(self) -> None:
        authentic = _write_inventory(
            self.external / "authentic.json",
            secrets={
                "SYNTHETIC_ALPHA": SYNTHETIC_ALPHA,
                "SYNTHETIC_BETA": SYNTHETIC_BETA,
            },
        )
        digest = hashlib.sha256(authentic.read_bytes()).hexdigest()
        identity = inventory._identity(os.lstat(authentic))
        with self.assertRaisesRegex(
            inventory.InventoryError, "cannot self-authorize"
        ) as raised:
            inventory.authenticate_inventory_contract(
                revision="rev-test-1",
                labels=("SYNTHETIC_ALPHA", "SYNTHETIC_BETA"),
                digest=digest,
                identity=identity,
            )
        _assert_undisclosed(
            self, str(raised.exception), SYNTHETIC_ALPHA, SYNTHETIC_BETA
        )
        loaded = self.load(authentic)
        self.assertFalse(loaded.authenticated)
        with self.assertRaisesRegex(inventory.InventoryError, "not release coverage"):
            list(inventory.release_secret_values(loaded))

    def test_inventory_contract_file_must_match_current_identity(self) -> None:
        authentic = _write_inventory(
            self.external / "current.json",
            secrets={
                "SYNTHETIC_ALPHA": SYNTHETIC_ALPHA,
                "SYNTHETIC_BETA": SYNTHETIC_BETA,
            },
        )
        digest = hashlib.sha256(authentic.read_bytes()).hexdigest()
        identity = inventory._identity(os.lstat(authentic))
        contract_path = self.external / "current.contract.json"
        contract_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "contract": inventory.CONTRACT_NAME,
                    "revision": "rev-test-1",
                    "labels": ["SYNTHETIC_ALPHA", "SYNTHETIC_BETA"],
                    "inventory_digest": digest,
                    "identity": list(identity),
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        contract_path.chmod(0o600)
        with self.assertRaisesRegex(
            inventory.InventoryError, "cannot self-authorize"
        ) as raised:
            inventory.load_inventory_contract(
                contract_path, repository_root=self.repo
            )
        _assert_undisclosed(
            self, str(raised.exception), SYNTHETIC_ALPHA, SYNTHETIC_BETA
        )
        self.assertFalse(self.load(authentic).authenticated)

    def test_parent_path_swap_is_rejected(self) -> None:
        nested = self.external / "nested"
        nested.mkdir()
        good = _write_inventory(
            nested / "inventory.json",
            secrets={"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
        )
        other = self.external / "other"
        other.mkdir()
        _write_inventory(
            other / "inventory.json",
            secrets={"SYNTHETIC_BETA": SYNTHETIC_BETA},
        )
        file_index = len(good.parts) - 2

        def swap_parent(path, index):
            if index != file_index:
                return
            os.rename(nested, self.external / "nested-old")
            os.rename(other, nested)

        inventory._POST_PARENT_BIND_HOOK = swap_parent
        try:
            with self.assertRaisesRegex(inventory.InventoryError, "replaced") as raised:
                self.load(good)
            _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA, SYNTHETIC_BETA)
        finally:
            inventory._POST_PARENT_BIND_HOOK = None

    def test_parent_swap_restore_is_rejected(self) -> None:
        nested = self.external / "nested"
        nested.mkdir()
        good = _write_inventory(
            nested / "inventory.json",
            secrets={"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
        )
        other = self.external / "other"
        other.mkdir()
        _write_inventory(
            other / "inventory.json",
            secrets={"SYNTHETIC_BETA": SYNTHETIC_BETA},
        )
        nested_old = self.external / "nested-old"
        parent_index = len(good.parts) - 3
        file_index = len(good.parts) - 2

        def swap_restore(_path, index):
            if index == parent_index:
                os.rename(nested, nested_old)
                os.rename(other, nested)
            elif index == file_index:
                os.rename(nested, other)
                os.rename(nested_old, nested)

        inventory._POST_PARENT_BIND_HOOK = swap_restore
        try:
            with self.assertRaisesRegex(inventory.InventoryError, "replaced"):
                self.load(good)
        finally:
            inventory._POST_PARENT_BIND_HOOK = None

    def test_parent_symlink_replacement_is_rejected(self) -> None:
        nested = self.external / "nested"
        nested.mkdir()
        good = _write_inventory(nested / "inventory.json")
        other = self.external / "other"
        other.mkdir()
        _write_inventory(
            other / "inventory.json",
            secrets={"SYNTHETIC_BETA": SYNTHETIC_BETA},
        )
        file_index = len(good.parts) - 2

        def replace_with_symlink(_path, index):
            if index != file_index:
                return
            os.rename(nested, self.external / "nested-old")
            os.symlink(other, nested)

        inventory._POST_PARENT_BIND_HOOK = replace_with_symlink
        try:
            with self.assertRaisesRegex(inventory.InventoryError, "replaced"):
                self.load(good)
        finally:
            inventory._POST_PARENT_BIND_HOOK = None

    def test_external_parent_substitution_is_rejected(self) -> None:
        nested = self.external / "nested"
        nested.mkdir()
        good = _write_inventory(nested / "inventory.json")
        outside = pathlib.Path(tempfile.mkdtemp(prefix="wins-ext-parent-"))
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        _write_inventory(
            outside / "inventory.json",
            secrets={"SYNTHETIC_BETA": SYNTHETIC_BETA},
        )
        file_index = len(good.parts) - 2

        def substitute(_path, index):
            if index != file_index:
                return
            os.rename(nested, self.external / "nested-old")
            os.rename(outside, nested)

        inventory._POST_PARENT_BIND_HOOK = substitute
        try:
            with self.assertRaisesRegex(inventory.InventoryError, "replaced"):
                self.load(good)
        finally:
            inventory._POST_PARENT_BIND_HOOK = None

    def test_parent_replaced_with_file_is_rejected(self) -> None:
        nested = self.external / "nested"
        nested.mkdir()
        good = _write_inventory(nested / "inventory.json")
        file_index = len(good.parts) - 2

        def replace_with_file(_path, index):
            if index != file_index:
                return
            os.rename(nested, self.external / "nested-old")
            nested.write_bytes(b"not-a-directory-parent")

        inventory._POST_PARENT_BIND_HOOK = replace_with_file
        try:
            with self.assertRaisesRegex(
                inventory.InventoryError, "replaced|missing or unreadable"
            ):
                self.load(good)
        finally:
            inventory._POST_PARENT_BIND_HOOK = None

    def test_unrelated_tempdir_sibling_churn_is_not_substitution(self) -> None:
        path = _write_inventory(
            self.external / "inventory.json",
            secrets={"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
        )
        stop = threading.Event()
        errors: list[BaseException] = []
        cycles = {"n": 0}

        def worker() -> None:
            try:
                while not stop.is_set():
                    _churn_tempdir_siblings(f"thr-{cycles['n']}")
                    cycles["n"] += 1
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        inventory._POST_PARENT_BIND_HOOK = _churn_bound_ancestors
        try:
            for _ in range(8):
                loaded = self.load(path)
                self.assertEqual(loaded.labels, ("SYNTHETIC_ALPHA",))
                self.assertEqual(loaded.label_count, 1)
        finally:
            inventory._POST_PARENT_BIND_HOOK = None
            stop.set()
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertGreater(cycles["n"], 0)

    def test_directory_is_rejected(self) -> None:
        directory = self.external / "not-a-file"
        directory.mkdir()
        with self.assertRaisesRegex(inventory.InventoryError, "regular non-symlink"):
            self.load(directory)

    def test_release_coverage_fails_closed_without_authenticated_contract(self) -> None:
        path = _write_inventory(self.external / "coverage.json")
        with self.assertRaisesRegex(
            inventory.InventoryError, "requires load_authenticated_secret_inventory"
        ):
            inventory.load_secret_inventory(
                path, repository_root=ROOT, require_authenticated=True
            )
        loaded = self.load(path)
        self.assertFalse(loaded.authenticated)
        with self.assertRaisesRegex(
            inventory.InventoryError, "not release coverage"
        ) as raised:
            list(inventory.release_secret_values(loaded))
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)
        self.assertIn("server-side", str(raised.exception))

    def test_candidate_contract_cannot_stream_release_secret_values(self) -> None:
        path = _write_inventory(
            self.external / "auth.json",
            secrets={
                "SYNTHETIC_ALPHA": SYNTHETIC_ALPHA,
                "SYNTHETIC_BETA": SYNTHETIC_BETA,
            },
        )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        identity = inventory._identity(os.lstat(path))
        with self.assertRaisesRegex(
            inventory.InventoryError, "cannot self-authorize"
        ) as raised:
            inventory.authenticate_inventory_contract(
                revision="rev-test-1",
                labels=("SYNTHETIC_ALPHA", "SYNTHETIC_BETA"),
                digest=digest,
                identity=identity,
            )
        _assert_undisclosed(
            self, str(raised.exception), SYNTHETIC_ALPHA, SYNTHETIC_BETA
        )
        loaded = self.load(path)
        with self.assertRaisesRegex(inventory.InventoryError, "not release coverage"):
            list(inventory.release_secret_values(loaded))

    def test_negative_mutation_of_authenticated_digest_is_rejected(self) -> None:
        path = _write_inventory(self.external / "mutated.json")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        identity = inventory._identity(os.lstat(path))
        mutated = "0" if digest[0] != "0" else "1"
        with self.assertRaisesRegex(
            inventory.InventoryError, "cannot self-authorize"
        ):
            inventory.authenticate_inventory_contract(
                revision="rev-test-1",
                labels=("SYNTHETIC_ALPHA",),
                digest=mutated + digest[1:],
                identity=identity,
            )


if __name__ == "__main__":
    unittest.main()
