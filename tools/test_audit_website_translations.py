#!/usr/bin/env python3
"""Hostile and honest tests for the website translation audit boundary."""

from __future__ import annotations

import builtins
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("audit_website_translations.py")
REPO_ROOT = MODULE_PATH.parent.parent
VALIDATOR_SOURCE = REPO_ROOT / "tools" / "website_localization_contract.py"
CONTRACT_SOURCE = REPO_ROOT / "localization" / "website" / "contract.json"
SPEC = importlib.util.spec_from_file_location(
    "audit_website_translations_under_test", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load audit_website_translations.py")
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


DRIFT_KEYS = (
    "Affordable Yet Great Product!",
    "Win's VPN",
    "Winn Protocol\u2122",
    "apps.irs.gov/app/eos",
)


def minimal_contract(
    *,
    required: tuple[str, ...] = ("Email", "Hello"),
    inherited_translate_no_only: tuple[str, ...] = ("Frozen",),
    mixed_context: tuple[str, ...] = (),
    locales: tuple[str, ...] = ("en", "fr"),
    nontranslatable: tuple[str, ...] | None = None,
    drift_keys: tuple[str, ...] = DRIFT_KEYS,
    drift_classification: str = "nontranslatable",
) -> dict[str, object]:
    excluded = nontranslatable or tuple((*DRIFT_KEYS, "Brand"))
    return {
        "key_classification": {
            "translatable_static_keys": sorted(required),
            "nontranslatable_static_keys": sorted(excluded),
            "inherited_translate_no_only_keys": sorted(
                inherited_translate_no_only
            ),
            "mixed_translate_context_keys": sorted(mixed_context),
            "runtime_audit_nontranslatable_drift": {
                "classification": drift_classification,
                "keys": sorted(drift_keys),
            },
        },
        "instant_locale_inventory": {
            "locales": [
                {"code": locale, "name": locale.upper()} for locale in locales
            ],
        },
        "compiler_output": {"locale_order": list(locales)},
    }


def complete_translations(
    contract: dict[str, object],
) -> dict[str, dict[str, str]]:
    classification = contract["key_classification"]
    inventory = contract["instant_locale_inventory"]
    assert isinstance(classification, dict)
    assert isinstance(inventory, dict)
    required = classification["translatable_static_keys"]
    locales = [item["code"] for item in inventory["locales"]]
    assert isinstance(required, list)
    translations: dict[str, dict[str, str]] = {
        "en": {key: key for key in required},
    }
    for locale in locales[1:]:
        translations[locale] = {
            key: f"{locale} translation: {key}" for key in required
        }
    return translations


class StrictLocaleJsonTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name).resolve(strict=True)
        self.locale_path = self.root / "major.json"

    def load(self, payload: str | bytes) -> dict[str, dict[str, str]]:
        if isinstance(payload, bytes):
            self.locale_path.write_bytes(payload)
        else:
            self.locale_path.write_text(payload, encoding="utf-8")
        return AUDIT.load_translations(self.locale_path)

    def test_honest_locale_document_is_preserved(self) -> None:
        expected = {
            "en": {"Hello": "Hello", "Email": "Email"},
            "fr": {"Hello": "Bonjour", "Email": "Courriel"},
        }
        self.assertEqual(
            self.load(
                '{"en":{"Hello":"Hello","Email":"Email"},'
                '"fr":{"Hello":"Bonjour","Email":"Courriel"}}'
            ),
            expected,
        )

    def test_duplicate_top_level_locale_is_rejected(self) -> None:
        with self.assertRaisesRegex(AUDIT.TranslationAuditError, "duplicate JSON key"):
            self.load('{"fr":{"Hello":"Bonjour"},"fr":{"Hello":"Salut"}}')

    def test_duplicate_nested_translation_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(AUDIT.TranslationAuditError, "duplicate JSON key"):
            self.load('{"fr":{"Hello":"Bonjour","Hello":"Salut"}}')

    def test_non_finite_values_and_float_overflow_are_rejected(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(constant=constant):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "non-finite JSON value",
                ):
                    self.load(f'{{"fr":{{"Hello":{constant}}}}}')

    def test_malformed_json_is_rejected(self) -> None:
        for payload in (
            '{"fr":{"Hello":"Bonjour"}',
            '{"fr": [}',
            '{"fr":{"Hello":"Bonjour",}}',
            "not-json",
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "malformed locale JSON",
                ):
                    self.load(payload)

    def test_bom_invalid_utf8_and_surrogates_are_rejected(self) -> None:
        cases = (
            (b'\xef\xbb\xbf{"fr":{}}', "BOM"),
            (b'{"fr":{"Hello":"\xff"}}', "strict UTF-8"),
            (b'{"fr":{"Hello":"\\ud800"}}', "Unicode surrogate"),
        )
        for payload, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(AUDIT.TranslationAuditError, pattern):
                    self.load(payload)

    def test_non_object_root_is_rejected(self) -> None:
        for payload in ("[]", "null", '"fr"', "1", "true"):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "root must be an object",
                ):
                    self.load(payload)

    def test_non_object_locale_mapping_is_rejected(self) -> None:
        for value in ("[]", "null", '"Bonjour"', "1", "true"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "translations must be an object",
                ):
                    self.load(f'{{"fr":{value}}}')

    def test_empty_source_and_non_string_translation_are_rejected(self) -> None:
        with self.assertRaisesRegex(AUDIT.TranslationAuditError, "invalid source key"):
            self.load('{"fr":{"":"Bonjour"}}')
        for value in ("{}", "[]", "null", "1", "true"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "must be a string",
                ):
                    self.load(f'{{"fr":{{"Hello":{value}}}}}')


class BoundTreeFixture:
    COPIED_PATHS = (
        "tools/audit_website_translations.py",
        "tools/website_localization_contract.py",
        "localization/website/contract.json",
        "web/index.html",
        "web/i18n/languages.json",
        "web/i18n/major.json",
    )

    def __init__(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary_directory.name).resolve(strict=True)
        for relative in self.COPIED_PATHS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / relative, destination)

    def cleanup(self) -> None:
        self._temporary_directory.cleanup()

    def run_audit(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            AUDIT.RELEASE_LAUNCHER_PATH,
            "-I",
            "-S",
            str(self.root / AUDIT.AUDITOR_PATH),
            "--repo",
            str(self.root),
            *arguments,
        ]
        child_environment = os.environ.copy()
        if environment is not None:
            child_environment.update(environment)
        return subprocess.run(
            command,
            cwd=self.root,
            env=child_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )


class ContractBindingTests(unittest.TestCase):
    def fixture(self) -> BoundTreeFixture:
        fixture = BoundTreeFixture()
        self.addCleanup(fixture.cleanup)
        return fixture

    def test_honest_bound_snapshot_loads_and_reports_exact_contract_counts(self) -> None:
        fixture = self.fixture()
        contract, translations = AUDIT.load_bound_contract_and_translations(
            fixture.root
        )
        semantics = AUDIT.contract_audit_semantics(contract)
        self.assertEqual(len(semantics["required"]), 379)
        self.assertEqual(len(semantics["nontranslatable"]), 37)
        self.assertEqual(len(semantics["translate_no_only"]), 83)
        self.assertEqual(len(semantics["mixed_context"]), 4)
        self.assertEqual(len(semantics["locale_order"]), 39)
        self.assertEqual(semantics["drift_keys"], DRIFT_KEYS)
        self.assertEqual(list(translations), list(semantics["locale_order"]))

    def test_contract_source_mismatch_is_rejected(self) -> None:
        fixture = self.fixture()
        index_path = fixture.root / AUDIT.INDEX_PATH
        index_path.write_bytes(index_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "English source SHA-256 mismatch",
        ):
            AUDIT.load_bound_contract_and_translations(fixture.root)

    def test_language_and_aggregate_order_drift_is_rejected(self) -> None:
        fixture = self.fixture()
        aggregate_path = fixture.root / AUDIT.AGGREGATE_PATH
        document = json.loads(aggregate_path.read_text(encoding="utf-8"))
        reordered = dict(reversed(list(document.items())))
        aggregate_path.write_text(
            json.dumps(reordered, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "language order does not match the contract",
        ):
            AUDIT.load_bound_contract_and_translations(fixture.root)

    def test_hostile_aggregate_json_fails_before_audit(self) -> None:
        cases = (
            (b'{"en":{},"en":{}}', "duplicate JSON key"),
            (b'{"en":{"Hello":NaN}}', "non-finite JSON value"),
            (b'{"en":', "malformed web/i18n/major.json"),
        )
        for payload, pattern in cases:
            with self.subTest(pattern=pattern):
                fixture = BoundTreeFixture()
                try:
                    (fixture.root / AUDIT.AGGREGATE_PATH).write_bytes(payload)
                    with self.assertRaisesRegex(
                        AUDIT.TranslationAuditError,
                        pattern,
                    ):
                        AUDIT.load_bound_contract_and_translations(fixture.root)
                finally:
                    fixture.cleanup()

    def test_missing_and_wrong_contract_or_validator_hash_fail_closed(self) -> None:
        cases = (
            (
                AUDIT.CONTRACT_PATH,
                AUDIT.ACCEPTED_CONTRACT_SHA256,
                "localization contract",
            ),
            (
                AUDIT.VALIDATOR_PATH,
                AUDIT.ACCEPTED_VALIDATOR_SHA256,
                "contract validator",
            ),
        )
        for relative, expected_hash, label in cases:
            with self.subTest(relative=relative, condition="missing"):
                temporary = tempfile.TemporaryDirectory()
                try:
                    root = Path(temporary.name).resolve(strict=True)
                    with self.assertRaisesRegex(
                        AUDIT.TranslationAuditError,
                        "unavailable or unsafe|missing or unsafe",
                    ):
                        with AUDIT.BoundTree(root, label="test root") as tree:
                            tree.read_file(
                                relative,
                                expected_sha256=expected_hash,
                                label=label,
                            )
                finally:
                    temporary.cleanup()
            with self.subTest(relative=relative, condition="wrong hash"):
                temporary = tempfile.TemporaryDirectory()
                try:
                    root = Path(temporary.name).resolve(strict=True)
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"substituted\n")
                    with self.assertRaisesRegex(
                        AUDIT.TranslationAuditError,
                        "SHA-256 mismatch",
                    ):
                        with AUDIT.BoundTree(root, label="test root") as tree:
                            tree.read_file(
                                relative,
                                expected_sha256=expected_hash,
                                label=label,
                            )
                finally:
                    temporary.cleanup()

    def test_identical_bytes_at_alternate_paths_are_rejected(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve(strict=True)
        alternatives = {
            "contract_path": "localization/website/contract-copy.json",
            "validator_path": "tools/website_localization_contract_copy.py",
            "index_path": "web/index-copy.html",
            "aggregate_path": "web/i18n/major-copy.json",
        }
        source_by_argument = {
            "contract_path": CONTRACT_SOURCE,
            "validator_path": VALIDATOR_SOURCE,
            "index_path": REPO_ROOT / AUDIT.INDEX_PATH,
            "aggregate_path": REPO_ROOT / AUDIT.AGGREGATE_PATH,
        }
        for argument, relative in alternatives.items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_by_argument[argument], destination)
            with self.subTest(argument=argument):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "path substitution rejected",
                ):
                    AUDIT.load_bound_contract_and_translations(
                        root,
                        **{argument: relative},
                    )

    def test_symlinked_leaf_and_parent_substitution_are_rejected(self) -> None:
        for parent_symlink in (False, True):
            with self.subTest(parent_symlink=parent_symlink):
                temporary = tempfile.TemporaryDirectory()
                try:
                    root = Path(temporary.name).resolve(strict=True)
                    outside = root / "outside"
                    outside.mkdir()
                    copied = outside / "validator.py"
                    shutil.copyfile(VALIDATOR_SOURCE, copied)
                    if parent_symlink:
                        (root / "tools").symlink_to(outside, target_is_directory=True)
                        copied.rename(outside / "website_localization_contract.py")
                    else:
                        (root / "tools").mkdir()
                        (root / AUDIT.VALIDATOR_PATH).symlink_to(copied)
                    with self.assertRaisesRegex(
                        AUDIT.TranslationAuditError,
                        "unavailable or unsafe|missing or unsafe",
                    ):
                        with AUDIT.BoundTree(root, label="test root") as tree:
                            tree.read_file(
                                AUDIT.VALIDATOR_PATH,
                                expected_sha256=AUDIT.ACCEPTED_VALIDATOR_SHA256,
                                label="contract validator",
                            )
                finally:
                    temporary.cleanup()


class DescriptorClosureHostileTests(unittest.TestCase):
    def temporary_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name).resolve(strict=True)

    def test_root_swap_and_restore_is_rejected(self) -> None:
        outer = self.temporary_root() / "outer"
        root = outer / "repo"
        root.mkdir(parents=True)
        with AUDIT.BoundTree(root, label="test repository") as tree:
            held = outer / "repo-held"
            root.rename(held)
            root.mkdir()
            root.rmdir()
            held.rename(root)
            with self.assertRaisesRegex(
                AUDIT.TranslationAuditError,
                "mutated during audit|removed or substituted",
            ):
                tree.revalidate()

    def test_higher_parent_swap_and_restore_is_rejected(self) -> None:
        outer = self.temporary_root() / "outer"
        higher = outer / "higher"
        root = higher / "repo"
        root.mkdir(parents=True)
        with AUDIT.BoundTree(root, label="test repository") as tree:
            held = outer / "higher-held"
            higher.rename(held)
            higher.mkdir()
            higher.rmdir()
            held.rename(higher)
            with self.assertRaisesRegex(
                AUDIT.TranslationAuditError,
                "mutated during audit|removed or substituted",
            ):
                tree.revalidate()

    def test_leaf_swap_and_restore_is_rejected(self) -> None:
        root = self.temporary_root()
        leaf = root / "payload.json"
        leaf.write_bytes(b"{}\n")
        with AUDIT.BoundTree(root, label="test repository") as tree:
            tree.read_file("payload.json", label="test payload")
            held = root / "payload-held.json"
            leaf.rename(held)
            leaf.write_bytes(b"{}\n")
            leaf.unlink()
            held.rename(leaf)
            with self.assertRaisesRegex(
                AUDIT.TranslationAuditError,
                "mutated during audit|removed or substituted",
            ):
                tree.revalidate()

    def test_aggregate_mutation_after_capture_is_rejected(self) -> None:
        fixture = BoundTreeFixture()
        self.addCleanup(fixture.cleanup)
        aggregate = fixture.root / AUDIT.AGGREGATE_PATH
        with AUDIT.BoundTree(fixture.root, label="test repository") as tree:
            AUDIT._capture_repository_inputs(tree)
            aggregate.write_bytes(aggregate.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                AUDIT.TranslationAuditError,
                "mutated during audit",
            ):
                tree.revalidate()

    def test_locale_source_mutation_after_capture_is_rejected(self) -> None:
        fixture = BoundTreeFixture()
        self.addCleanup(fixture.cleanup)
        locale = fixture.root / AUDIT.LOCALE_SOURCE_DIRECTORY / "my.json"
        locale.parent.mkdir(parents=True)
        locale.write_bytes(b"{}\n")
        with AUDIT.BoundTree(fixture.root, label="test repository") as tree:
            _, _, missing = AUDIT._capture_repository_inputs(tree)
            self.assertNotIn("my", missing)
            locale.write_bytes(b'{"changed":true}\n')
            with self.assertRaisesRegex(
                AUDIT.TranslationAuditError,
                "mutated during audit",
            ):
                tree.revalidate()

    def test_hardlinked_aggregate_is_rejected(self) -> None:
        fixture = BoundTreeFixture()
        self.addCleanup(fixture.cleanup)
        aggregate = fixture.root / AUDIT.AGGREGATE_PATH
        os.link(aggregate, fixture.root / "aggregate-hardlink.json")
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "exactly one hard link",
        ):
            with AUDIT.BoundTree(fixture.root, label="test repository") as tree:
                AUDIT._capture_repository_inputs(tree)

    def test_fifo_aggregate_is_rejected_without_blocking(self) -> None:
        fixture = BoundTreeFixture()
        self.addCleanup(fixture.cleanup)
        aggregate = fixture.root / AUDIT.AGGREGATE_PATH
        aggregate.unlink()
        os.mkfifo(aggregate)
        started = time.monotonic()
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "not a regular file|missing or unsafe",
        ):
            with AUDIT.BoundTree(fixture.root, label="test repository") as tree:
                AUDIT._capture_repository_inputs(tree)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_writable_unsafe_parent_is_rejected(self) -> None:
        root = self.temporary_root() / "unsafe"
        root.mkdir()
        root.chmod(0o777)
        self.addCleanup(root.chmod, 0o700)
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "unsafe writable permissions",
        ):
            AUDIT.BoundTree(root, label="test repository")

    def test_duplicate_non_ascii_key_diagnostic_is_ascii_and_exact(self) -> None:
        with self.assertRaises(AUDIT.TranslationAuditError) as caught:
            AUDIT.strict_json_loads(
                b'{"caf\xc3\xa9":1,"caf\xc3\xa9":2}',
                label="hostile JSON",
            )
        diagnostic = str(caught.exception)
        self.assertEqual(diagnostic, "duplicate JSON key: 'caf\\xe9'")
        self.assertTrue(diagnostic.isascii())


class ProductionAuthorityHostileTests(unittest.TestCase):
    def fixture(self) -> BoundTreeFixture:
        fixture = BoundTreeFixture()
        self.addCleanup(fixture.cleanup)
        return fixture

    def test_fabricated_complete_aggregate_cannot_pass_without_locale_sources(self) -> None:
        fixture = self.fixture()
        contract = json.loads(CONTRACT_SOURCE.read_text(encoding="utf-8"))
        fabricated = complete_translations(contract)
        (fixture.root / AUDIT.AGGREGATE_PATH).write_text(
            json.dumps(fabricated, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        result = fixture.run_audit("--show", "0")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            "aggregate: untranslated=0 missing=0 english_fallback=0\n",
            result.stdout,
        )
        self.assertIn("compiler_closure=UNCOMPILED", result.stdout)
        self.assertIn("production_status=UNCOMPILED authority=NONE", result.stdout)
        self.assertNotIn("production_status=PASS", result.stdout)

    def test_release_launcher_discards_hostile_path_and_python_environment(self) -> None:
        fixture = self.fixture()
        result = fixture.run_audit(
            "--show",
            "0",
            environment={
                "PATH": "/private/tmp/poisoned-path",
                "PYTHONPATH": "/private/tmp/poisoned-pythonpath",
                "PYTHONSTARTUP": "/private/tmp/poisoned-startup.py",
            },
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("authority_boundary interpreter=ReleasePython-3.14.7", result.stdout)
        self.assertIn("compiler_closure=UNCOMPILED", result.stdout)

    def test_nonisolated_direct_entry_reexecs_into_fresh_release_boundary(self) -> None:
        fixture = self.fixture()
        result = subprocess.run(
            [
                AUDIT.RELEASE_LAUNCHER_PATH,
                str(fixture.root / AUDIT.AUDITOR_PATH),
                "--repo",
                str(fixture.root),
                "--show",
                "0",
            ],
            cwd=fixture.root,
            env=os.environ.copy(),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("authority_boundary interpreter=ReleasePython-3.14.7", result.stdout)
        self.assertIn("compiler_closure=UNCOMPILED", result.stdout)

    def test_imported_main_refuses_compile_exec_import_module_and_path_poisoning(
        self,
    ) -> None:
        originals = {
            "compile": builtins.compile,
            "exec": builtins.exec,
            "__import__": builtins.__import__,
        }
        module_name = "_winsvpn_retained_website_localization_contract"
        absent = object()
        original_module = sys.modules.get(module_name, absent)
        original_path = os.environ.get("PATH")

        def poisoned(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise AssertionError("ambient builtin was used")

        errors = io.StringIO()
        try:
            builtins.compile = poisoned
            builtins.exec = poisoned
            builtins.__import__ = poisoned
            sys.modules[module_name] = object()
            os.environ["PATH"] = "/private/tmp/poisoned-path"
            with redirect_stderr(errors):
                result = AUDIT.main([])
        finally:
            builtins.compile = originals["compile"]
            builtins.exec = originals["exec"]
            builtins.__import__ = originals["__import__"]
            if original_module is absent:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = original_module
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path
        self.assertEqual(result, 2)
        self.assertIn("imported mode is diagnostic-only", errors.getvalue())

    def test_duplicate_non_ascii_aggregate_diagnostic_is_ascii(self) -> None:
        fixture = self.fixture()
        (fixture.root / AUDIT.AGGREGATE_PATH).write_bytes(
            b'{"caf\xc3\xa9":{},"caf\xc3\xa9":{}}'
        )
        result = fixture.run_audit("--show", "0")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.isascii())
        self.assertIn("caf\\xe9", result.stderr)
        self.assertNotIn("caf\xe9", result.stderr)


class StaticContractAuditTests(unittest.TestCase):
    def render(
        self,
        contract: dict[str, object],
        translations: dict[str, dict[str, str]],
        *,
        show: int = 12,
    ) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            result = AUDIT.report_audit(contract, translations, show=show)
        return result, output.getvalue()

    def test_complete_multilanguage_fixture_is_diagnostically_clean_only(self) -> None:
        contract = minimal_contract(
            required=("Email", "Hello", "Shared"),
            locales=("en", "fr", "es"),
        )
        result, output = self.render(contract, complete_translations(contract))
        self.assertEqual(result, 0)
        self.assertIn("diagnostic_result_authority=NONE\n", output)
        self.assertNotIn("production_status=PASS", output)
        self.assertIn("contract_counts translatable_static_keys=3 ", output)
        self.assertIn(
            "fr: untranslated=0 missing=0 english_fallback=0\n",
            output,
        )
        self.assertIn(
            "es: untranslated=0 missing=0 english_fallback=0\n",
            output,
        )
        self.assertTrue(
            output.endswith(
                "aggregate: untranslated=0 missing=0 english_fallback=0\n"
            )
        )

    def test_inherited_translate_no_only_key_is_excluded(self) -> None:
        contract = minimal_contract(
            required=("Hello",),
            inherited_translate_no_only=("Frozen child text",),
        )
        translations = complete_translations(contract)
        result, output = self.render(contract, translations)
        self.assertEqual(result, 0)
        self.assertIn("inherited_translate_no_only_keys=1", output)
        self.assertNotIn("Frozen child text\n", output)

    def test_inherited_translate_no_key_in_aggregate_is_not_an_exemption(self) -> None:
        contract = minimal_contract(
            required=("Hello",),
            inherited_translate_no_only=("Frozen child text",),
        )
        translations = complete_translations(contract)
        translations["fr"]["Frozen child text"] = "Texte fige"
        result, output = self.render(contract, translations)
        self.assertEqual(result, 1)
        self.assertIn("fr_contract_parity out_of_contract=1\n", output)

    def test_nontranslatable_key_in_aggregate_is_not_an_exemption(self) -> None:
        contract = minimal_contract(required=("Hello",))
        translations = complete_translations(contract)
        translations["fr"]["Brand"] = "Marque"
        result, output = self.render(contract, translations)
        self.assertEqual(result, 1)
        self.assertIn("fr_contract_parity out_of_contract=1\n", output)

    def test_mixed_translate_context_key_remains_required(self) -> None:
        contract = minimal_contract(
            required=("Hello", "Shared context"),
            inherited_translate_no_only=("Frozen child text",),
            mixed_context=("Shared context",),
        )
        translations = complete_translations(contract)
        del translations["fr"]["Shared context"]
        result, output = self.render(contract, translations)
        self.assertEqual(result, 1)
        self.assertIn("mixed_translate_context_keys=1", output)
        self.assertIn(
            "fr: untranslated=1 missing=1 english_fallback=0\n",
            output,
        )
        self.assertIn("  - Shared context\n", output)

    def test_all_four_accepted_drift_keys_are_reported_and_excluded(self) -> None:
        contract = minimal_contract(required=("Hello",))
        semantics = AUDIT.contract_audit_semantics(contract)
        self.assertEqual(semantics["drift_keys"], DRIFT_KEYS)
        for key in DRIFT_KEYS:
            with self.subTest(key=key):
                self.assertIn(key, semantics["nontranslatable"])
                self.assertNotIn(key, semantics["required"])
        result, output = self.render(contract, complete_translations(contract))
        self.assertEqual(result, 0)
        self.assertIn(
            "runtime_audit_exclusion_drift "
            "classification=nontranslatable keys=4 unresolved=0\n",
            output,
        )
        for key in DRIFT_KEYS:
            self.assertIn(f"  - {AUDIT._ascii_text(key)}\n", output)

    def test_unresolved_drift_semantics_fail_closed(self) -> None:
        wrong_classification = minimal_contract(
            drift_classification="translatable"
        )
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "exclusion drift is unresolved",
        ):
            AUDIT.contract_audit_semantics(wrong_classification)

        missing_exclusion = minimal_contract(
            nontranslatable=tuple(key for key in DRIFT_KEYS if key != DRIFT_KEYS[0])
        )
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "exclusion drift is unresolved",
        ):
            AUDIT.contract_audit_semantics(missing_exclusion)

        required_drift = minimal_contract(
            required=("Hello", DRIFT_KEYS[0]),
        )
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "classifications overlap",
        ):
            AUDIT.contract_audit_semantics(required_drift)

    def test_missing_and_exact_english_fallback_are_distinct_failures(self) -> None:
        contract = minimal_contract(required=("Email", "Hello", "Shared"))
        translations = complete_translations(contract)
        del translations["fr"]["Email"]
        translations["fr"]["Hello"] = "Hello"
        result, output = self.render(contract, translations, show=3)
        self.assertEqual(result, 1)
        self.assertIn(
            "fr: untranslated=2 missing=1 english_fallback=1\n",
            output,
        )
        self.assertIn(
            "aggregate: untranslated=2 missing=1 english_fallback=1\n",
            output,
        )

    def test_alias_key_cannot_satisfy_exact_contract_requirement(self) -> None:
        required = "Privacy Policy, Terms, Acceptable Use, and Liability"
        alias = "Terms, Privacy Policy, Acceptable Use, and Liability"
        contract = minimal_contract(required=(required,))
        translations = complete_translations(contract)
        del translations["fr"][required]
        translations["fr"][alias] = "Conditions traduites"
        result, output = self.render(contract, translations)
        self.assertEqual(result, 1)
        self.assertIn("missing=1 english_fallback=0", output)
        self.assertIn("fr_contract_parity out_of_contract=1\n", output)

    def test_extra_aggregate_key_is_not_assumed_to_be_dynamic(self) -> None:
        contract = minimal_contract(required=("Hello",))
        translations = complete_translations(contract)
        translations["fr"]["Runtime API string"] = "Runtime API string"
        result, output = self.render(contract, translations)
        self.assertEqual(result, 1)
        self.assertIn(
            "scope=contract_bound_static_keys dynamic_runtime_strings=not_covered "
            "aggregate_extra_keys=out_of_contract_not_dynamic\n",
            output,
        )
        self.assertIn("fr_contract_parity out_of_contract=1\n", output)
        self.assertIn("  - Runtime API string\n", output)

    def test_english_mapping_parity_is_fail_closed(self) -> None:
        contract = minimal_contract(required=("Email", "Hello"))
        translations = complete_translations(contract)
        del translations["en"]["Email"]
        translations["en"]["Hello"] = "Not source identity"
        translations["en"]["Legacy alias"] = "Legacy alias"
        result, output = self.render(contract, translations)
        self.assertEqual(result, 1)
        self.assertIn(
            "en_contract_parity failures=3 missing=1 identity_mismatch=1 "
            "out_of_contract=1\n",
            output,
        )

    def test_instant_locale_descriptors_and_compiler_order_are_exact(self) -> None:
        cases = []
        missing_name = minimal_contract()
        del missing_name["instant_locale_inventory"]["locales"][1]["name"]
        cases.append(missing_name)
        extra_field = minimal_contract()
        extra_field["instant_locale_inventory"]["locales"][1]["instant"] = True
        cases.append(extra_field)
        invalid_code = minimal_contract()
        invalid_code["instant_locale_inventory"]["locales"][1]["code"] = "FR"
        cases.append(invalid_code)
        blank_name = minimal_contract()
        blank_name["instant_locale_inventory"]["locales"][1]["name"] = " "
        cases.append(blank_name)
        reordered = minimal_contract()
        reordered["compiler_output"]["locale_order"] = ["fr", "en"]
        cases.append(reordered)
        for contract in cases:
            with self.subTest(contract=contract):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "instant locale descriptor|language/instant order",
                ):
                    AUDIT.contract_audit_semantics(contract)

    def test_language_missing_extra_and_order_drift_fail_closed(self) -> None:
        contract = minimal_contract(required=("Hello",), locales=("en", "fr"))
        honest = complete_translations(contract)
        cases = (
            {"en": honest["en"]},
            {"en": honest["en"], "fr": honest["fr"], "es": {}},
            {"fr": honest["fr"], "en": honest["en"]},
        )
        for translations in cases:
            with self.subTest(locales=list(translations)):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "language order does not match",
                ):
                    AUDIT.audit_translations(contract, translations)

    def test_required_values_must_be_nonempty_and_trimmed(self) -> None:
        contract = minimal_contract(required=("Hello",))
        for value in ("", " Bonjour", "Bonjour "):
            translations = complete_translations(contract)
            translations["fr"]["Hello"] = value
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    AUDIT.TranslationAuditError,
                    "must be nonempty and trimmed",
                ):
                    AUDIT.audit_translations(contract, translations)

    def test_current_real_audit_remains_failure_without_readiness_claim(self) -> None:
        contract, translations = AUDIT.load_bound_contract_and_translations(REPO_ROOT)
        result, output = self.render(contract, translations, show=0)
        self.assertEqual(result, 1)
        self.assertIn(
            "aggregate: untranslated=8891 missing=8891 english_fallback=0\n",
            output,
        )
        self.assertIn(
            "en_contract_parity failures=397 missing=358 "
            "identity_mismatch=0 out_of_contract=39\n",
            output,
        )
        self.assertIn("out_of_contract=5250\n", output)
        self.assertIn("dynamic_runtime_strings=not_covered", output)
        process = subprocess.run(
            [
                AUDIT.RELEASE_LAUNCHER_PATH,
                "-I",
                "-S",
                str(MODULE_PATH),
                "--repo",
                str(REPO_ROOT),
                "--show",
                "0",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertIn(
            "aggregate: untranslated=8891 missing=8891 english_fallback=0\n",
            process.stdout,
        )
        self.assertIn("compiler_closure=UNCOMPILED", process.stdout)
        self.assertIn("production_status=UNCOMPILED authority=NONE", process.stdout)
        self.assertNotIn("production_status=PASS", process.stdout)


class MainBoundaryTests(unittest.TestCase):
    def test_imported_main_refuses_production_authority(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = AUDIT.main(["--index", "web/other.html"])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("imported mode is diagnostic-only", errors.getvalue())

    def test_imported_internal_authority_entry_is_also_refused(self) -> None:
        with self.assertRaisesRegex(
            AUDIT.TranslationAuditError,
            "imported mode is diagnostic-only",
        ):
            AUDIT._authoritative_main(AUDIT.argparse.Namespace())

    def test_direct_main_reports_path_substitution_as_fail_closed_error(self) -> None:
        fixture = BoundTreeFixture()
        self.addCleanup(fixture.cleanup)
        result = fixture.run_audit("--index", "web/other.html")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("path substitution rejected", result.stderr)

    def test_negative_show_is_rejected(self) -> None:
        contract = minimal_contract(required=("Hello",))
        with self.assertRaisesRegex(AUDIT.TranslationAuditError, "zero or greater"):
            AUDIT.report_audit(contract, complete_translations(contract), show=-1)


GET_SECTION = (
    "The Get Win's VPN section offers monthly, yearly, and lifetime options. "
    "PayPal subscription renewals and provisioning are intended to sync "
    "automatically with the control hub."
)
DOUBLE_VPN = (
    "Double VPN is planned to pass traffic through a physically controlled "
    "North America core server before the final VPN exit. Until that "
    "infrastructure is live, the app continues with the normal Winn "
    "Protocol\u00ae route."
)


class TranslationIntegrityAuditTests(unittest.TestCase):
    """Defect shapes taken from the pre-repair web/i18n/major.json."""

    def defects(self, source: str, translated: str) -> list[str]:
        return AUDIT.translation_integrity_defects(source, translated)

    def assertDefect(self, source: str, translated: str, needle: str) -> None:
        found = self.defects(source, translated)
        self.assertTrue(
            any(needle in item for item in found),
            f"{needle!r} not reported for {translated!r}: {found!r}",
        )

    def test_leaked_placeholder_envelopes_are_reported(self) -> None:
        cases = (
            ("Win's VPN logo", "Logo ZZZWINVPPNPLAINZZZ"),
            (
                "Win's VPN\u2122 | AI-Powered No-Logs VPN Made in America",
                "\u0417\u0417\u0417\u0412\u0418\u041d\u0412\u041f\u041d"
                "\u0420\u0415\u0413\u0417\u0417\u0417 | VPN",
            ),
            (DOUBLE_VPN, "\u1218\u1295\u1308\u12f5 ZZWINNPROTOCOLZZZ"),
            (GET_SECTION, "Usasishaji wa ZZZPAYPAYPALZZZ"),
            ("Android and Windows first, then macOS/iOS.", "macOS/ZZIOSZZZZ"),
            ("Android Demo", "ZZZANDROIDZZ \u0e01\u0e32\u0e23\u0e2a\u0e32\u0e18\u0e34\u0e15"),
            ("Win's VPN app", "ZXQ742693851QXZ app"),
            ("Win's VPN app", "__\u200bWINSVPN_BRAND__ app"),
            ("Integrate iOS and MacOS apps.", "\u1ee9ng d\u1ee5ng iOSBRAND v\u00e0 MacOS"),
            ("Android VpnService disclosure.", "ANDROIDMARKA VPNH\u0130ZMET MARKASI"),
        )
        for source, translated in cases:
            with self.subTest(translated=translated):
                self.assertDefect(source, translated, "placeholder token")

    def test_legitimate_words_and_orthography_are_not_defects(self) -> None:
        cases = (
            ("Use the app securely.", "Utilizza l'app in sicurezza."),
            ("Access", "Hozz\u00e1f\u00e9r\u00e9s"),
            ("Censorship", "Zensur und Zugriff"),
            ("Sign in", "Zaloguj si\u0119"),
            ("The XXVI century", "Le XXVI si\u00e8cle"),
            ("NGFW Deep Packet Inspection", "NGFW Deep Packet Inspection"),
            ("It disconnects.", "\u0642\u0637\u0639 \u0645\u06cc\u200c\u0634\u0648\u062f."),
            ("Wrap", "\u09b0\u200d\u09cd\u09af\u09be\u09aa"),
            (
                "Lao text",
                "\u0ec1\u0e9a\u0ea1\u200b\u0ea1\u0eb2",
            ),
            (
                "Payments are processed by PayPal.",
                "Maksut k\u00e4sitell\u00e4\u00e4n PayPalilla.",
            ),
            ("Assassination will not stop Win's VPN.", "Win's VPN'i durdurmayacak."),
            ("Watch Demo (iOS)", "Demoyu izle (iOS)"),
            ("Zali Win", "Zali Win"),
        )
        for source, translated in cases:
            with self.subTest(translated=translated):
                self.assertEqual(self.defects(source, translated), [])

    def test_stray_capital_z_glued_to_names_is_reported(self) -> None:
        cases = (
            ("When Android asks, allow Win's VPN.", "ZAndroid ZWin's VPN"),
            ("Android and Windows first, then macOS/iOS.", "Android Windows macOS/ZiOS"),
            ("Use the Winn Protocol\u00ae route.", "Winn Protocol\u00aeZ route"),
            ("Windows demo video", "WindowsZ"),
            ("private connection layer", "private connection layerZ"),
        )
        for source, translated in cases:
            with self.subTest(translated=translated):
                self.assertDefect(source, translated, "stray Z")

    def test_doubled_or_space_adjacent_zero_width_is_reported(self) -> None:
        self.assertDefect(
            "caused by misuse",
            "causados \u200b\u200bpor mal uso",
            "zero-width",
        )
        self.assertDefect("los", "staan \u200blos", "zero-width")
        self.assertDefect("loss", "lo\u200b\u200bss", "zero-width")

    def test_changed_protected_names_are_reported(self) -> None:
        cases = (
            ("Coalition Inc.", "Coalici\u00f3n Inc.", "'Coalition Inc.' occurs 0"),
            ("Win Empire LLC logo", "Gagner le logo Empire LLC", "'Win Empire LLC'"),
            ("Win's VPN logo", "Wins VPN-logo", "\"Win's VPN\" occurs 0"),
            ("Win's VPN logo", "Win\u2019s VPN logo", "\"Win's VPN\" occurs 0"),
            ("Android safety mode.", "\u5b89\u5353\u5b89\u5168\u6a21\u5f0f\u3002", "'Android'"),
            (
                "One year of Win's VPN protection and Winn Protocol\u00ae access.",
                "Win's VPN \u0938\u0941\u0930\u0915\u094d\u0937\u093e "
                "\u0935\u093f\u0928\u094d\u0928 \u092a\u094d\u0930\u094b\u091f\u094b\u0915\u0949\u0932\u2122",
                "'Winn Protocol\u00ae' occurs 0",
            ),
            (
                "See the Windows desktop app connect securely.",
                "Windows app connect with Winn Protocol\u00ae.",
                "'Winn Protocol\u00ae' occurs 1 times; English source has 0",
            ),
            (
                "Payments are processed by PayPal.",
                "Pagamentos PayPal PayPal.",
                "'PayPal' occurs 2",
            ),
        )
        for source, translated, needle in cases:
            with self.subTest(translated=translated):
                self.assertDefect(source, translated, needle)
        self.assertEqual(
            self.defects("Win Empire LLC logo", "Logo Win Empire LLC"),
            [],
        )
        self.assertDefect(
            "Apple Maps on Apple platforms",
            "Apple \u5730\u56fe\uff08Apple \u5e73\u53f0\uff09",
            "'Apple Maps' occurs 0",
        )
        self.assertEqual(
            self.defects("Hybrid ZZTOPKEM768 exchange", "Echange hybride ZZTOPKEM768"),
            [],
        )

    def test_appended_bracketed_name_absent_from_english_is_reported(self) -> None:
        self.assertDefect(
            "Win's VPN logo",
            "Win's VPN-logo (Win's VPN).",
            "appended bracketed name",
        )
        self.assertDefect(
            GET_SECTION,
            "Win's VPN PayPal ofrece opciones (PayPal).",
            "appended bracketed name",
        )
        self.assertEqual(
            self.defects("Linux (coming soon)", "Linux (bient\u00f4t)"),
            [],
        )

    def test_value_copied_into_another_locale_is_reported(self) -> None:
        sentence = "Release candidates are being prepared for the app stores."
        spanish = "Se est\u00e1n preparando versiones candidatas para las tiendas."
        translations = {
            "en": {sentence: sentence},
            "es": {sentence: spanish},
            "bn": {sentence: spanish},
            "sv": {"Video": "Video", sentence: "Versionskandidater f\u00f6rbereds."},
            "no": {"Video": "Video"},
        }
        findings = AUDIT.catalog_integrity_findings(translations)
        self.assertEqual(
            sorted((locale, key) for locale, _defect, key in findings),
            [("bn", sentence), ("es", sentence)],
        )

    def test_report_audit_fails_closed_on_integrity_defects(self) -> None:
        contract = minimal_contract(required=("Email", "Hello"))
        translations = complete_translations(contract)
        output = io.StringIO()
        with redirect_stdout(output):
            clean = AUDIT.report_audit(contract, translations, show=0)
        self.assertEqual(clean, 0)
        self.assertIn("translation_integrity failures=0\n", output.getvalue())
        translations["fr"]["Hello"] = "ZZZWINVPPNPLAINZZZ bonjour"
        output = io.StringIO()
        with redirect_stdout(output):
            dirty = AUDIT.report_audit(contract, translations, show=5)
        self.assertEqual(dirty, 1)
        self.assertIn("translation_integrity failures=1\n", output.getvalue())
        self.assertIn("  - fr: placeholder token", output.getvalue())

    def test_repository_catalog_has_no_integrity_defects(self) -> None:
        translations = AUDIT.load_translations(REPO_ROOT / "web" / "i18n" / "major.json")
        findings = AUDIT.catalog_integrity_findings(translations)
        self.assertEqual(
            findings[:20],
            [],
            f"{len(findings)} translation integrity defects in web/i18n/major.json",
        )

    def test_compiled_locale_files_match_the_catalog(self) -> None:
        translations = AUDIT.load_translations(REPO_ROOT / "web" / "i18n" / "major.json")
        locale_directory = REPO_ROOT / "web" / "i18n" / "locales"
        self.assertEqual(
            sorted(path.stem for path in locale_directory.glob("*.json")),
            sorted(translations),
        )
        for locale, mapping in translations.items():
            with self.subTest(locale=locale):
                compiled = json.loads(
                    (locale_directory / f"{locale}.json").read_text(encoding="utf-8")
                )
                self.assertEqual(compiled, mapping)


if __name__ == "__main__":
    unittest.main()
