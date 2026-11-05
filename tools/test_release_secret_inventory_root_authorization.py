#!/usr/bin/env python3
"""Release loader tests for the inventory named by WINS_RELEASE_SECRET_INVENTORY.

The file keeps its historical name. The former root:wheel authorization under
/Library/WinsVPN is gone; these tests pin the replacement contract: an exact
absolute path outside the repository, a regular single-link file owned by the
current user with mode 0600 or stricter, strict parsing, and refusal when the
inventory is missing or invalid. All labels and values are synthetic fixtures.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import release_secret_inventory as inventory  # noqa: E402


ENV = "WINS_RELEASE_SECRET_INVENTORY"
REVISION = "env-inventory-test-1"
LABELS = ("SYNTHETIC_ALPHA", "SYNTHETIC_BETA")
SECRETS = {
    "SYNTHETIC_ALPHA": "synthetic-alpha-value-001",
    "SYNTHETIC_BETA": "synthetic-beta-value-002",
}


def _document(secrets: dict[str, str] | None = None) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "revision": REVISION,
            "secrets": SECRETS if secrets is None else secrets,
        },
        separators=(",", ":"),
    ).encode("utf-8")


class EnvironmentInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_root = pathlib.Path(
            tempfile.mkdtemp(prefix="wins-env-inventory-")
        ).resolve()
        self.addCleanup(shutil.rmtree, self.temp_root, ignore_errors=True)
        self.external = self.temp_root / "external"
        self.external.mkdir()
        self.inventory_path = self.external / "inventory.json"
        self._write(self.inventory_path)
        environment = mock.patch.dict(os.environ, {ENV: str(self.inventory_path)})
        environment.start()
        self.addCleanup(environment.stop)
        self.addCleanup(self._clear_hooks)

    def _clear_hooks(self) -> None:
        inventory._POST_PARENT_BIND_HOOK = None

    def _write(
        self,
        path: pathlib.Path,
        payload: bytes | None = None,
        mode: int = 0o600,
    ) -> pathlib.Path:
        path.write_bytes(_document() if payload is None else payload)
        path.chmod(mode)
        return path

    def _load(self, root: pathlib.Path = ROOT) -> inventory.SecretInventory:
        return inventory.load_authenticated_secret_inventory(repository_root=root)

    def test_environment_inventory_is_release_coverage_without_disclosure(self) -> None:
        loaded = self._load()
        self.assertTrue(loaded.authenticated)
        self.assertEqual(loaded.labels, LABELS)
        self.assertEqual(dict(inventory.release_secret_values(loaded)), SECRETS)
        summary = loaded.public_summary()
        self.assertEqual(summary["inventory_source"], ENV)
        self.assertTrue(summary["authenticated"])
        public = json.dumps(summary, sort_keys=True) + repr(loaded)
        for value in SECRETS.values():
            self.assertNotIn(value, public)

    def test_owner_read_only_mode_is_accepted(self) -> None:
        self.inventory_path.chmod(0o400)
        self.assertTrue(self._load().authenticated)

    def test_environment_name_is_the_public_constant(self) -> None:
        self.assertEqual(inventory.INVENTORY_ENV, ENV)

    def test_root_custody_is_gone(self) -> None:
        for name in (
            "AUTHORIZATION_DIRECTORY",
            "AUTHORIZATION_PATH",
            "INVENTORY_PATH",
            "AUTHORIZATION_ROOT_UID",
            "AUTHORIZATION_WHEEL_GID",
            "_read_custody_file",
            "_controller_digest",
            "_parse_authorization_document",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(inventory, name))
        source = (TOOLS / "release_secret_inventory.py").read_text(encoding="utf-8")
        self.assertNotIn("/Library/WinsVPN", source)
        self.assertNotIn("release_uid", source)

    def test_missing_or_empty_environment_refuses(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV, None)
            with self.assertRaisesRegex(inventory.InventoryError, "not configured"):
                self._load()
        with mock.patch.dict(os.environ, {ENV: ""}):
            with self.assertRaisesRegex(inventory.InventoryError, "not configured"):
                self._load()

    def test_missing_inventory_file_refuses(self) -> None:
        missing = self.external / "absent.json"
        with mock.patch.dict(os.environ, {ENV: str(missing)}):
            with self.assertRaisesRegex(
                inventory.InventoryError, "secret inventory is missing or unreadable"
            ):
                self._load()

    def test_relative_noncanonical_and_traversal_paths_refuse(self) -> None:
        for raw in (
            "inventory.json",
            "./inventory.json",
            str(self.external) + "/./inventory.json",
            str(self.external) + "//inventory.json",
            str(self.external) + "/../external/inventory.json",
            str(self.inventory_path) + "/",
            " " + str(self.inventory_path),
            str(self.inventory_path) + "\n",
        ):
            with self.subTest(raw=raw):
                with mock.patch.dict(os.environ, {ENV: raw}):
                    with self.assertRaisesRegex(
                        inventory.InventoryError, "exact absolute path"
                    ):
                        self._load()

    def test_inventory_inside_repository_refuses(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "outside the repository"):
            self._load(root=self.temp_root)
        fake_repository = self.temp_root / "repository"
        inside = fake_repository / "secrets"
        inside.mkdir(parents=True)
        self._write(inside / "inventory.json")
        alias = self.temp_root / "alias"
        os.symlink(inside, alias)
        with mock.patch.dict(os.environ, {ENV: str(alias / "inventory.json")}):
            with self.assertRaisesRegex(
                inventory.InventoryError, "outside the repository"
            ):
                self._load(root=fake_repository)

    def test_relative_repository_root_refuses(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "root must be absolute"):
            inventory.load_authenticated_secret_inventory(
                repository_root=pathlib.Path("relative-repository")
            )

    def test_inventory_owned_by_another_user_refuses(self) -> None:
        other_uid = os.getuid() + 1
        with mock.patch.object(inventory.os, "getuid", return_value=other_uid):
            with self.assertRaisesRegex(
                inventory.InventoryError, "owned by the current user"
            ):
                self._load()

    def test_group_world_or_execute_modes_refuse(self) -> None:
        for mode in (0o640, 0o604, 0o660, 0o644, 0o700, 0o610, 0o601):
            with self.subTest(mode=oct(mode)):
                self.inventory_path.chmod(mode)
                with self.assertRaisesRegex(
                    inventory.InventoryError, "mode 0600 or stricter"
                ):
                    self._load()

    def test_symlink_hardlink_fifo_and_directory_refuse(self) -> None:
        real = self.external / "inventory.real"
        self.inventory_path.rename(real)
        os.symlink(real, self.inventory_path)
        with self.assertRaisesRegex(inventory.InventoryError, "regular non-symlink"):
            self._load()

        self.inventory_path.unlink()
        real.rename(self.inventory_path)
        hardlink = self.external / "inventory.hardlink"
        os.link(self.inventory_path, hardlink)
        with self.assertRaisesRegex(inventory.InventoryError, "link count 1"):
            self._load()

        hardlink.unlink()
        self.inventory_path.unlink()
        os.mkfifo(self.inventory_path, 0o600)
        with self.assertRaisesRegex(inventory.InventoryError, "regular non-symlink"):
            self._load()

        self.inventory_path.unlink()
        self.inventory_path.mkdir()
        with self.assertRaisesRegex(inventory.InventoryError, "regular non-symlink"):
            self._load()

    def test_final_path_swap_refuses(self) -> None:
        replacement = self._write(
            self.external / "replacement.json",
            _document({"SYNTHETIC_ALPHA": "replacement-alpha-value-9"}),
        )
        final_index = len(self.inventory_path.parts[1:]) - 1

        def swap(path: pathlib.Path, index: int) -> None:
            if path == self.inventory_path and index == final_index:
                os.replace(replacement, self.inventory_path)

        inventory._POST_PARENT_BIND_HOOK = swap
        with self.assertRaisesRegex(inventory.InventoryError, "replaced"):
            self._load()

    def test_strict_parsing_still_applies(self) -> None:
        canonical = _document()
        cases = {
            "duplicate JSON key": canonical.replace(
                b'{"schema_version":1,', b'{"schema_version":1,"schema_version":1,', 1
            ),
            "top-level schema is not exact": canonical[:-1] + b',"extra":1}',
            "transcript/message schema": json.dumps(
                {
                    "schema_version": 1,
                    "revision": REVISION,
                    "secrets": {"SYNTHETIC_ALPHA": {"messages": []}},
                }
            ).encode("utf-8"),
            "length is outside": _document({"SYNTHETIC_ALPHA": "short"}),
            "invalid ASCII label": _document({"lowercase": SECRETS["SYNTHETIC_ALPHA"]}),
            "at least one label": _document({}),
            "not valid JSON": b"{",
        }
        for message, payload in cases.items():
            with self.subTest(message=message):
                self._write(self.inventory_path, payload)
                with self.assertRaisesRegex(inventory.InventoryError, message):
                    self._load()

    def test_secret_bearing_path_refuses(self) -> None:
        leaking = self._write(
            self.external / (SECRETS["SYNTHETIC_ALPHA"] + ".json")
        )
        with mock.patch.dict(os.environ, {ENV: str(leaking)}):
            with self.assertRaisesRegex(
                inventory.InventoryError, "must not carry secret material"
            ) as raised:
                self._load()
        self.assertNotIn(SECRETS["SYNTHETIC_ALPHA"], str(raised.exception))

    def test_release_values_reread_inventory_immediately_before_use(self) -> None:
        loaded = self._load()
        self._write(
            self.inventory_path,
            _document(
                {
                    "SYNTHETIC_ALPHA": "rewritten-alpha-value-101",
                    "SYNTHETIC_BETA": "rewritten-beta-value-102",
                }
            ),
        )
        with self.assertRaisesRegex(inventory.InventoryError, "changed before release use"):
            list(inventory.release_secret_values(loaded))

        self._write(self.inventory_path)
        loaded = self._load()
        other = self._write(self.external / "other.json")
        with mock.patch.dict(os.environ, {ENV: str(other)}):
            with self.assertRaisesRegex(
                inventory.InventoryError, "changed before release use"
            ):
                list(inventory.release_secret_values(loaded))

        loaded = self._load()
        self.inventory_path.unlink()
        with self.assertRaisesRegex(
            inventory.InventoryError, "secret inventory is missing or unreadable"
        ):
            list(inventory.release_secret_values(loaded))

    def test_release_values_refuse_a_rebound_inventory_path(self) -> None:
        loaded = self._load()
        binding = loaded._authorization
        moved = inventory._make_authenticated_inventory(
            loaded,
            inventory._InventoryAuthorization(
                revision=binding.revision,
                labels=binding.labels,
                inventory_digest=binding.inventory_digest,
                inventory_identity=binding.inventory_identity,
                inventory_path=self.external / "moved.json",
                repository_root=binding.repository_root,
            ),
        )
        self.assertTrue(moved.authenticated)
        with mock.patch.object(
            inventory, "load_authenticated_secret_inventory", return_value=moved
        ):
            with self.assertRaisesRegex(
                inventory.InventoryError, "changed before release use"
            ):
                list(inventory.release_secret_values(loaded))

    def test_in_process_secret_tuple_replacement_never_reaches_release_stream(self) -> None:
        loaded = self._load()
        object.__setattr__(
            loaded,
            "_secrets",
            (
                ("SYNTHETIC_ALPHA", "forged-alpha-value-901"),
                ("SYNTHETIC_BETA", "forged-beta-value-902"),
            ),
        )
        self.assertTrue(loaded.authenticated)
        released = dict(inventory.release_secret_values(loaded))
        self.assertEqual(released, SECRETS)
        self.assertNotIn("forged-alpha-value-901", released.values())

    def test_public_constructor_and_parser_loader_are_not_release_coverage(self) -> None:
        with self.assertRaises(TypeError):
            inventory.SecretInventory(
                REVISION,
                SECRETS,
                authenticated=True,  # type: ignore[call-arg]
            )
        parsed = inventory.load_secret_inventory(
            self.inventory_path,
            repository_root=ROOT,
        )
        self.assertFalse(parsed.authenticated)
        with self.assertRaisesRegex(inventory.InventoryError, "not release coverage"):
            list(parsed.stream_secret_values())
        with self.assertRaises(AttributeError):
            parsed.authenticated = True  # type: ignore[misc]
        object.__setattr__(parsed, "_authorization", True)
        self.assertFalse(parsed.authenticated)
        with self.assertRaisesRegex(inventory.InventoryError, "not release coverage"):
            list(inventory.release_secret_values(parsed))
        with self.assertRaisesRegex(
            inventory.InventoryError, "requires load_authenticated_secret_inventory"
        ):
            inventory.load_secret_inventory(
                self.inventory_path,
                repository_root=ROOT,
                require_authenticated=True,
            )

    def test_legacy_contract_apis_fail_closed(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "cannot self-authorize"):
            inventory.authenticate_inventory_contract(
                revision=REVISION,
                labels=LABELS,
                digest="1" * 64,
                identity=(1,) * inventory.IDENTITY_FIELD_COUNT,
            )
        with self.assertRaisesRegex(inventory.InventoryError, "cannot self-authorize"):
            inventory.load_inventory_contract(
                self.inventory_path,
                repository_root=ROOT,
            )
        with self.assertRaisesRegex(inventory.InventoryError, "cannot self-authorize"):
            inventory.load_secret_inventory(
                self.inventory_path,
                repository_root=ROOT,
                contract=inventory.InventoryContract(
                    REVISION,
                    LABELS,
                    "1" * 64,
                    (1,) * inventory.IDENTITY_FIELD_COUNT,
                ),
            )

    def test_descriptor_relative_open_and_stat_are_hard_requirements(self) -> None:
        with mock.patch.object(
            inventory,
            "_DESCRIPTOR_RELATIVE_OPEN_SUPPORTED",
            False,
        ):
            with self.assertRaisesRegex(inventory.InventoryError, "descriptor-relative"):
                self._load()

    def test_unrelated_ancestor_sibling_churn_does_not_false_fail(self) -> None:
        stop = threading.Event()
        errors: list[BaseException] = []

        def churn() -> None:
            sequence = 0
            try:
                while not stop.is_set():
                    sibling = self.temp_root / f"churn-{sequence}"
                    sibling.mkdir()
                    sibling.rmdir()
                    sequence += 1
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=churn, daemon=True)
        worker.start()
        try:
            for _ in range(12):
                self.assertTrue(self._load().authenticated)
        finally:
            stop.set()
            worker.join(timeout=5)
        self.assertFalse(errors)


if __name__ == "__main__":
    unittest.main()
