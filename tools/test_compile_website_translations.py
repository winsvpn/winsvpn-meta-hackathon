#!/usr/bin/env python3
"""Adversarial temporary-fixture tests for the website translation compiler."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
TOOLS_DIRECTORY = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIRECTORY.parent
COMPILER_PATH = TOOLS_DIRECTORY / "compile_website_translations.py"
VALIDATOR_PATH = TOOLS_DIRECTORY / "website_localization_contract.py"
CONTRACT_PATH = REPO_ROOT / "localization/website/contract.json"


def _load_module(name: str, path: Path) -> object:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"unable to load {path.name}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


COMPILER = _load_module("compile_website_translations_under_test", COMPILER_PATH)
VALIDATOR = _load_module("website_localization_contract_for_compiler_test", VALIDATOR_PATH)
COMPILER_BYTES = COMPILER_PATH.read_bytes()
VALIDATOR_BYTES = VALIDATOR_PATH.read_bytes()
CONTRACT_BYTES = CONTRACT_PATH.read_bytes()
CONTRACT_DOCUMENT = VALIDATOR.validate_contract_document(
    VALIDATOR.strict_json_loads(
        CONTRACT_BYTES,
        label=COMPILER.PRODUCTION_CONTRACT_PATH,
    )
)
INDEX_BYTES = (REPO_ROOT / VALIDATOR.INDEX_PATH).read_bytes()
LANGUAGES_BYTES = (REPO_ROOT / VALIDATOR.LANGUAGES_PATH).read_bytes()
AUDIT_BYTES = (REPO_ROOT / VALIDATOR.AUDIT_PATH).read_bytes()


class RepositoryFixture:
    def __init__(self, owner: unittest.TestCase) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        owner.addCleanup(self._temporary.cleanup)
        container = Path(self._temporary.name).resolve()
        self.root = container / "repo"
        self.root.mkdir()
        self.write_bytes(COMPILER.PRODUCTION_COMPILER_PATH, COMPILER_BYTES)
        self.write_bytes(COMPILER.PRODUCTION_VALIDATOR_PATH, VALIDATOR_BYTES)
        self.write_bytes(COMPILER.PRODUCTION_CONTRACT_PATH, CONTRACT_BYTES)
        self.contract = copy.deepcopy(CONTRACT_DOCUMENT)
        self.binding = COMPILER.PRODUCTION_BINDING
        self.copy_bound_english_sources()
        self.keys = list(
            self.contract["key_classification"]["translatable_static_keys"]
        )
        self.target_locales = [
            str(target["locale"])
            for target in self.contract["locale_sources"]["targets"]
        ]
        self.locale_documents: dict[str, dict[str, object]] = {}
        for locale in self.target_locales:
            document = self.locale_document(locale)
            self.locale_documents[locale] = document
            self.write_locale_document(locale, document)
        self.expected_document = self.compiler_output_document()
        self.expected_payload = VALIDATOR.canonical_json_bytes(
            self.expected_document,
            ensure_ascii=False,
        )
        self.write_bytes(COMPILER.EXPECTED_OUTPUT_PATH, self.expected_payload)

    def path(self, relative: str) -> Path:
        return self.root / relative

    def write_bytes(self, relative: str, payload: bytes) -> None:
        destination = self.path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)

    def write_text(self, relative: str, payload: str) -> None:
        self.write_bytes(relative, payload.encode("utf-8"))

    def write_json(self, relative: str, document: object) -> None:
        self.write_bytes(
            relative,
            VALIDATOR.canonical_json_bytes(document, ensure_ascii=False),
        )

    def sha256(self, relative: str) -> str:
        return hashlib.sha256(self.path(relative).read_bytes()).hexdigest()

    def copy_bound_english_sources(self) -> None:
        bound_sources = {
            VALIDATOR.INDEX_PATH: INDEX_BYTES,
            VALIDATOR.AUDIT_PATH: AUDIT_BYTES,
            VALIDATOR.LANGUAGES_PATH: LANGUAGES_BYTES,
        }
        for relative, payload in bound_sources.items():
            self.write_bytes(relative, payload)

    def translation_for(self, locale: str, key: str) -> str:
        return f"[{locale}] {key}"

    def locale_document(self, locale: str) -> dict[str, object]:
        keys = self.contract["key_classification"]["translatable_static_keys"]
        return {
            "schema": VALIDATOR.LOCALE_SOURCE_SCHEMA,
            "locale": locale,
            "english_source_identity_sha256": self.contract["english_source"][
                "identity_sha256"
            ],
            "instant_locale_inventory_sha256": self.contract[
                "instant_locale_inventory"
            ]["identity_sha256"],
            "translatable_static_keys_sha256": self.contract["key_classification"][
                "translatable_static_keys_sha256"
            ],
            "translations": {
                key: self.translation_for(locale, key)
                for key in keys
            },
        }

    def locale_path(self, locale: str) -> Path:
        return self.path(f"{COMPILER.EXPECTED_LOCALE_DIRECTORY}/{locale}.json")

    def write_locale_document(self, locale: str, document: object) -> None:
        self.write_bytes(
            f"{COMPILER.EXPECTED_LOCALE_DIRECTORY}/{locale}.json",
            VALIDATOR.canonical_json_bytes(document, ensure_ascii=False),
        )

    def compiler_output_document(self) -> dict[str, dict[str, str]]:
        keys = self.contract["key_classification"]["translatable_static_keys"]
        output: dict[str, dict[str, str]] = {}
        for locale in self.contract["compiler_output"]["locale_order"]:
            if locale == "en":
                output[locale] = {key: key for key in keys}
            else:
                output[locale] = dict(
                    self.locale_documents[locale]["translations"]
                )
        return output

    def compile(self, mode: str) -> object:
        return COMPILER._compile_repository_with_binding(
            self.root,
            mode=mode,
            binding=self.binding,
        )

    def public_compile(
        self,
        mode: str,
        *,
        timeout: float = 20.0,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (
                COMPILER.RELEASE_PYTHON_LAUNCHER,
                "-I",
                "-S",
                COMPILER.PRODUCTION_COMPILER_PATH,
                mode,
                "--repo",
                ".",
            ),
            cwd=self.root,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )


class CompilerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepositoryFixture(self)

    def assertCompilerError(self, pattern: str):
        return self.assertRaisesRegex(
            COMPILER.WebsiteTranslationCompilerError,
            pattern,
        )


class HonestCompilationTests(CompilerTestCase):
    def test_verify_is_read_only_and_reports_exact_deterministic_bytes(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()
        before_metadata = output.stat()
        result = self.fixture.compile("verify")
        after_metadata = output.stat()
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(after_metadata.st_ino, before_metadata.st_ino)
        self.assertEqual(after_metadata.st_mtime_ns, before_metadata.st_mtime_ns)
        self.assertEqual(result.mode, "verify")
        self.assertEqual(result.locale_count, len(self.fixture.target_locales) + 1)
        self.assertEqual(result.key_count, len(self.fixture.keys))
        self.assertEqual(result.payload_size, len(self.fixture.expected_payload))
        self.assertEqual(
            result.payload_sha256,
            hashlib.sha256(self.fixture.expected_payload).hexdigest(),
        )

    def test_create_then_verify_is_an_honest_deterministic_round_trip(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        created = self.fixture.compile("create")
        self.assertEqual(created.mode, "create")
        self.assertEqual(output.read_bytes(), self.fixture.expected_payload)
        sample_locale = self.fixture.target_locales[0]
        sample_key = self.fixture.keys[0]
        self.assertIn(
            self.fixture.translation_for(sample_locale, sample_key).encode("utf-8"),
            output.read_bytes(),
        )
        created_hash = hashlib.sha256(output.read_bytes()).hexdigest()
        verified = self.fixture.compile("verify")
        self.assertEqual(verified.payload_sha256, created_hash)
        self.assertEqual(output.read_bytes(), self.fixture.expected_payload)

    def test_only_contract_classified_translatable_keys_are_emitted(self) -> None:
        parsed = VALIDATOR.strict_json_loads(
            self.fixture.expected_payload,
            label="fixture output",
        )
        expected_keys = self.fixture.keys
        self.assertEqual(
            list(parsed),
            list(self.fixture.contract["compiler_output"]["locale_order"]),
        )
        for mapping in parsed.values():
            self.assertEqual(list(mapping), expected_keys)
            for excluded in self.fixture.contract["key_classification"][
                "nontranslatable_static_keys"
            ]:
                self.assertNotIn(excluded, mapping)

    def test_mode_must_be_explicit_and_known(self) -> None:
        for mode in ("", "write", "replace", "check"):
            with self.subTest(mode=mode):
                with self.assertCompilerError("explicitly 'verify' or 'create'"):
                    self.fixture.compile(mode)


class LocaleInventoryAndValueTests(CompilerTestCase):
    def test_missing_locale_is_rejected(self) -> None:
        self.fixture.locale_path("es").unlink()
        with self.assertCompilerError(r"inventory mismatch.*missing=\['es.json'\]"):
            self.fixture.compile("verify")

    def test_extra_locale_is_rejected(self) -> None:
        self.fixture.write_bytes(
            f"{COMPILER.EXPECTED_LOCALE_DIRECTORY}/zz.json",
            self.fixture.locale_path("fr").read_bytes(),
        )
        with self.assertCompilerError(r"inventory mismatch.*extra=\['zz.json'\]"):
            self.fixture.compile("verify")

    def test_english_locale_source_is_an_extra_locale(self) -> None:
        self.fixture.write_bytes(
            f"{COMPILER.EXPECTED_LOCALE_DIRECTORY}/en.json",
            self.fixture.locale_path("fr").read_bytes(),
        )
        with self.assertCompilerError(r"inventory mismatch.*extra=\['en.json'\]"):
            self.fixture.compile("verify")

    def test_missing_and_extra_translation_keys_are_rejected(self) -> None:
        for variant in ("missing", "extra"):
            with self.subTest(variant=variant):
                fixture = RepositoryFixture(self)
                document = copy.deepcopy(fixture.locale_documents["fr"])
                key = fixture.keys[-1]
                if variant == "missing":
                    document["translations"].pop(key)
                else:
                    document["translations"]["Unexpected"] = "Inattendu"
                fixture.write_locale_document("fr", document)
                with self.assertRaisesRegex(
                    COMPILER.WebsiteTranslationCompilerError,
                    "translation keys or order differ",
                ):
                    fixture.compile("verify")

    def test_reordered_translation_keys_are_rejected(self) -> None:
        document = copy.deepcopy(self.fixture.locale_documents["fr"])
        document["translations"] = dict(
            reversed(list(document["translations"].items()))
        )
        self.fixture.write_locale_document("fr", document)
        with self.assertCompilerError("translation keys or order differ"):
            self.fixture.compile("verify")

    def test_english_fallback_is_rejected(self) -> None:
        document = copy.deepcopy(self.fixture.locale_documents["fr"])
        key = self.fixture.keys[0]
        document["translations"][key] = key
        self.fixture.write_locale_document("fr", document)
        with self.assertCompilerError("not translation-ready"):
            self.fixture.compile("verify")

    def test_empty_untrimmed_and_non_string_values_are_rejected(self) -> None:
        for value in ("", "   ", " Bonjour", "Bonjour ", 7, None, True):
            with self.subTest(value=value):
                fixture = RepositoryFixture(self)
                document = copy.deepcopy(fixture.locale_documents["fr"])
                document["translations"][fixture.keys[0]] = value
                fixture.write_locale_document("fr", document)
                with self.assertRaisesRegex(
                    COMPILER.WebsiteTranslationCompilerError,
                    "not translation-ready",
                ):
                    fixture.compile("verify")

    def test_contract_exclusions_cannot_be_injected_as_extra_keys(self) -> None:
        document = copy.deepcopy(self.fixture.locale_documents["fr"])
        exclusions = self.fixture.contract["key_classification"][
            "nontranslatable_static_keys"
        ]
        document["translations"][exclusions[0]] = "Excluded translation one"
        document["translations"][exclusions[1]] = "Excluded translation two"
        self.fixture.write_locale_document("fr", document)
        with self.assertCompilerError("translation keys or order differ"):
            self.fixture.compile("verify")

    def test_cross_locale_schema_and_stale_bindings_are_rejected(self) -> None:
        variants = (
            (
                "missing-field",
                lambda document: document.pop("schema"),
                "keys or key order are invalid",
            ),
            (
                "unknown-field",
                lambda document: document.__setitem__("unexpected", "value"),
                "keys or key order are invalid",
            ),
            (
                "wrong-schema",
                lambda document: document.__setitem__("schema", "foreign-schema"),
                "unsupported locale-source schema",
            ),
            (
                "cross-locale",
                lambda document: document.__setitem__("locale", "es"),
                "locale-source identity mismatch",
            ),
        )
        for name, mutate, pattern in variants:
            with self.subTest(name=name):
                fixture = RepositoryFixture(self)
                document = copy.deepcopy(fixture.locale_documents["fr"])
                mutate(document)
                fixture.write_locale_document("fr", document)
                with self.assertRaisesRegex(
                    COMPILER.WebsiteTranslationCompilerError,
                    pattern,
                ):
                    fixture.compile("verify")

        for field in (
            "english_source_identity_sha256",
            "instant_locale_inventory_sha256",
            "translatable_static_keys_sha256",
        ):
            with self.subTest(stale_binding=field):
                fixture = RepositoryFixture(self)
                document = copy.deepcopy(fixture.locale_documents["fr"])
                document[field] = "0" * 64
                fixture.write_locale_document("fr", document)
                with self.assertRaisesRegex(
                    COMPILER.WebsiteTranslationCompilerError,
                    rf"locale-source binding drift.*{field}",
                ):
                    fixture.compile("verify")


class StrictJsonAndBindingTests(CompilerTestCase):
    def test_duplicate_locale_document_keys_are_rejected_at_every_depth(self) -> None:
        path = self.fixture.locale_path("fr")
        top_level = path.read_bytes().replace(
            b'  "locale": "fr",\n',
            b'  "locale": "fr",\n  "locale": "fr",\n',
            1,
        )
        path.write_bytes(top_level)
        with self.assertCompilerError("duplicate JSON key: 'locale'"):
            self.fixture.compile("verify")

        nested_fixture = RepositoryFixture(self)
        nested_path = nested_fixture.locale_path("fr")
        key = nested_fixture.keys[0]
        value = nested_fixture.translation_for("fr", key)
        line = (
            f"    {json.dumps(key, ensure_ascii=False)}: "
            f"{json.dumps(value, ensure_ascii=False)}"
        ).encode("utf-8")
        nested = nested_path.read_bytes().replace(
            line + b",\n",
            line + b",\n" + line + b",\n",
            1,
        )
        self.assertNotEqual(nested, nested_path.read_bytes())
        nested_path.write_bytes(nested)
        with self.assertRaisesRegex(
            COMPILER.WebsiteTranslationCompilerError,
            "duplicate JSON key",
        ):
            nested_fixture.compile("verify")

    def test_nan_and_infinity_are_rejected(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                fixture = RepositoryFixture(self)
                document = copy.deepcopy(fixture.locale_documents["fr"])
                document["translations"][fixture.keys[0]] = value
                payload = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode(
                    "utf-8"
                )
                fixture.locale_path("fr").write_bytes(payload)
                with self.assertRaisesRegex(
                    COMPILER.WebsiteTranslationCompilerError,
                    "non-finite JSON value",
                ):
                    fixture.compile("verify")

    def test_overflowing_finite_syntax_is_rejected(self) -> None:
        path = self.fixture.locale_path("fr")
        value = self.fixture.translation_for("fr", self.fixture.keys[0])
        encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
        payload = path.read_bytes().replace(encoded, b"1e9999", 1)
        self.assertNotEqual(payload, path.read_bytes())
        path.write_bytes(payload)
        with self.assertCompilerError("non-finite JSON value"):
            self.fixture.compile("verify")

    def test_bom_invalid_utf8_and_noncanonical_line_endings_are_rejected(self) -> None:
        value = self.fixture.translation_for("fr", self.fixture.keys[0])
        encoded = value.encode("utf-8")
        hostile_payloads = (
            lambda payload: b"\xef\xbb\xbf" + payload,
            lambda payload: payload.replace(encoded, b"\xff", 1),
            lambda payload: payload.replace(b"\n", b"\r\n"),
        )
        for mutate in hostile_payloads:
            with self.subTest(mutate=mutate):
                fixture = RepositoryFixture(self)
                path = fixture.locale_path("fr")
                path.write_bytes(mutate(path.read_bytes()))
                with self.assertRaises(COMPILER.WebsiteTranslationCompilerError):
                    fixture.compile("verify")

    def test_raw_contract_byte_drift_breaks_the_exact_binding(self) -> None:
        contract_path = self.fixture.path(COMPILER.PRODUCTION_CONTRACT_PATH)
        contract_path.write_bytes(contract_path.read_bytes() + b"\n")
        with self.assertCompilerError("contract binding mismatch"):
            self.fixture.compile("verify")

    def test_english_source_drift_breaks_the_contract_snapshot(self) -> None:
        index = self.fixture.path(VALIDATOR.INDEX_PATH)
        index.write_bytes(index.read_bytes() + b" ")
        with self.assertCompilerError(r"descriptor-bound source bytes.*english_source"):
            self.fixture.compile("verify")

    def test_contract_locks_locale_order_aliases_rtl_and_exclusions(self) -> None:
        for variant in ("locale-order", "alias", "rtl", "exclusion"):
            with self.subTest(variant=variant):
                fixture = RepositoryFixture(self)
                if variant == "locale-order":
                    languages = VALIDATOR.strict_json_loads(
                        fixture.path(VALIDATOR.LANGUAGES_PATH).read_bytes(),
                        label=VALIDATOR.LANGUAGES_PATH,
                    )
                    languages[1], languages[2] = languages[2], languages[1]
                    fixture.write_json(VALIDATOR.LANGUAGES_PATH, languages)
                else:
                    index = fixture.path(VALIDATOR.INDEX_PATH)
                    payload = index.read_bytes()
                    replacements = {
                        "alias": (
                            b'"Privacy Policy, Terms, Acceptable Use, and Liability":',
                            b'"Changed alias":',
                        ),
                        "rtl": (
                            b'const rtlLanguages = new Set(["ar", "fa", "iw", "ur"]);',
                            b'const rtlLanguages = new Set(["ar", "fa", "ur"]);',
                        ),
                        "exclusion": (b'        "A+",\n', b""),
                    }
                    before, after = replacements[variant]
                    mutated = payload.replace(before, after, 1)
                    self.assertNotEqual(mutated, payload)
                    index.write_bytes(mutated)
                with self.assertCompilerError(
                    r"descriptor-bound source bytes.*"
                    r"(english_source|instant_locale_inventory)"
                ):
                    fixture.compile("verify")

    def test_validator_byte_drift_breaks_the_exact_binding_before_execution(self) -> None:
        validator = self.fixture.path(COMPILER.PRODUCTION_VALIDATOR_PATH)
        validator.write_bytes(validator.read_bytes() + b"\n")
        with self.assertCompilerError("validator binding mismatch"):
            self.fixture.compile("verify")

    def test_audit_source_byte_drift_has_a_unique_binding_failure(self) -> None:
        original = COMPILER._build_expected_contract_from_bytes(
            VALIDATOR,
            index_payload=INDEX_BYTES,
            audit_path=COMPILER.PRODUCTION_AUDIT_PATH,
            audit_payload=AUDIT_BYTES,
            languages_payload=LANGUAGES_BYTES,
        )
        drifted_payload = AUDIT_BYTES + b"\n# classification-preserving drift\n"
        drifted = COMPILER._build_expected_contract_from_bytes(
            VALIDATOR,
            index_payload=INDEX_BYTES,
            audit_path=COMPILER.PRODUCTION_AUDIT_PATH,
            audit_payload=drifted_payload,
            languages_payload=LANGUAGES_BYTES,
        )
        self.assertEqual(
            original.document["key_classification"],
            drifted.document["key_classification"],
        )
        self.assertEqual(original.audit_path, drifted.audit_path)
        self.assertNotEqual(original.audit_sha256, drifted.audit_sha256)
        with self.assertCompilerError("audit source path is not authoritative"):
            COMPILER._build_expected_contract_from_bytes(
                VALIDATOR,
                index_payload=INDEX_BYTES,
                audit_path="tools/classification-equivalent-audit-copy.py",
                audit_payload=AUDIT_BYTES,
                languages_payload=LANGUAGES_BYTES,
            )
        audit = self.fixture.path(VALIDATOR.AUDIT_PATH)
        audit.write_bytes(drifted_payload)
        with self.assertCompilerError("audit source binding mismatch"):
            self.fixture.compile("verify")

    def test_production_binding_constants_match_copied_reviewed_sources(self) -> None:
        self.assertEqual(
            hashlib.sha256(VALIDATOR_BYTES).hexdigest(),
            COMPILER.PRODUCTION_VALIDATOR_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(AUDIT_BYTES).hexdigest(),
            COMPILER.PRODUCTION_AUDIT_SHA256,
        )
        self.assertEqual(VALIDATOR.AUDIT_PATH, COMPILER.PRODUCTION_AUDIT_PATH)
        self.assertEqual(
            self.fixture.binding.contract_path,
            COMPILER.PRODUCTION_CONTRACT_PATH,
        )

    def test_imported_entry_point_cannot_emit_production_authority(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()
        with self.assertCompilerError("imported library mode cannot emit"):
            COMPILER.compile_repository(self.fixture.root, mode="verify")
        with self.assertCompilerError("imported library mode cannot establish"):
            COMPILER._production_subprocess(self.fixture.root, mode="verify")
        with self.assertRaises(TypeError):
            COMPILER.compile_repository(
                self.fixture.root,
                mode="verify",
                binding=self.fixture.binding,
            )
        self.assertEqual(output.read_bytes(), before)

    def test_nondeterministic_serializer_is_rejected(self) -> None:
        original = COMPILER._canonical_output_bytes
        calls = 0

        def alternating(validator: object, document: object) -> bytes:
            nonlocal calls
            calls += 1
            payload = original(validator, document)
            return payload if calls % 2 else payload + b" "

        with mock.patch.object(
            COMPILER,
            "_canonical_output_bytes",
            side_effect=alternating,
        ):
            with self.assertCompilerError("serialization is nondeterministic"):
                self.fixture.compile("verify")


class ProductionBoundaryTests(CompilerTestCase):
    def test_public_boundary_uses_the_accepted_contract_without_overrides(self) -> None:
        self.assertEqual(
            hashlib.sha256(CONTRACT_BYTES).hexdigest(),
            COMPILER.PRODUCTION_CONTRACT_SHA256,
        )
        completed = self.fixture.public_compile("verify")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("compiler_output_verified", completed.stdout)
        self.assertIn(
            f"sha256={hashlib.sha256(self.fixture.expected_payload).hexdigest()}",
            completed.stdout,
        )

    def test_public_create_retains_exact_output_bytes(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        completed = self.fixture.public_compile("create")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("compiler_output_created", completed.stdout)
        self.assertEqual(output.read_bytes(), self.fixture.expected_payload)
        self.assertEqual(output.stat().st_size, len(self.fixture.expected_payload))

    def test_sibling_json_module_cannot_poison_the_public_worker(self) -> None:
        sentinel = self.fixture.path("sibling-json-executed")
        self.fixture.write_text(
            "tools/json.py",
            "from pathlib import Path\n"
            f"Path({str(sentinel)!r}).write_text('poisoned')\n"
            "raise SystemExit(0)\n",
        )
        completed = self.fixture.public_compile("verify")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("compiler_output_verified", completed.stdout)
        self.assertFalse(sentinel.exists())

    def test_worker_launch_descriptor_substitution_is_rejected(self) -> None:
        source = COMPILER_BYTES
        source = source.replace(
            b"            pass_fds = tuple(\n",
            b"            worker_launch_fd = os.dup(compiler_handle.fd)\n"
            b"            pass_fds = tuple(\n",
            1,
        )
        source = source.replace(
            b"                    + (runtime_fd, control_read, result_write)\n",
            b"                    + (\n"
            b"                        runtime_fd, control_read, result_write,\n"
            b"                        worker_launch_fd,\n"
            b"                    )\n",
            1,
        )
        source = source.replace(
            b'                    f"/dev/fd/{compiler_handle.fd}",\n',
            b'                    f"/dev/fd/{worker_launch_fd}",\n',
            1,
        )
        self.assertNotEqual(source, COMPILER_BYTES)
        self.fixture.write_bytes(COMPILER.PRODUCTION_COMPILER_PATH, source)
        completed = self.fixture.public_compile("verify")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            "isolated worker did not execute the retained compiler bytes",
            completed.stderr,
        )

    def test_rebound_popen_at_production_launch_is_rejected(self) -> None:
        needle = (
            b"            _attest_subprocess_launch_hooks()\n"
            b"            process = _BOUND_POPEN(\n"
        )
        replacement = (
            b"            subprocess.Popen = type(\n"
            b"                'HostilePopen', (_BOUND_POPEN,), {}\n"
            b"            )\n"
            + needle
        )
        source = COMPILER_BYTES.replace(needle, replacement, 1)
        self.assertNotEqual(source, COMPILER_BYTES)
        self.fixture.write_bytes(COMPILER.PRODUCTION_COMPILER_PATH, source)
        completed = self.fixture.public_compile("verify")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn("rebound subprocess launch hooks", completed.stderr)

    def test_modified_repository_compiler_copy_is_rejected(self) -> None:
        compiler = self.fixture.path(COMPILER.PRODUCTION_COMPILER_PATH)
        compiler.write_bytes(compiler.read_bytes() + b"\n# modified copy\n")
        completed = subprocess.run(
            (
                COMPILER.RELEASE_PYTHON_LAUNCHER,
                "-I",
                "-S",
                str(COMPILER_PATH),
                "verify",
                "--repo",
                str(self.fixture.root),
            ),
            cwd=REPO_ROOT,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            "repository compiler does not match the externally reviewed compiler bytes",
            completed.stderr,
        )

    def test_parent_load_then_compiler_path_replace_restore_is_rejected(self) -> None:
        compiler = self.fixture.path(COMPILER.PRODUCTION_COMPILER_PATH)
        loaded_marker = self.fixture.path(".compiler-parent-loaded")
        allow_open = self.fixture.path(".compiler-allow-open")
        opened_marker = self.fixture.path(".compiler-descriptor-opened")
        allow_read = self.fixture.path(".compiler-allow-read")
        gate = (
            b"if __name__ == '__main__':\n"
            + f"    Path({str(loaded_marker)!r}).write_bytes(b'loaded')\n".encode()
            + b"    gate_deadline = time.monotonic() + 10.0\n"
            + f"    while not Path({str(allow_open)!r}).exists():\n".encode()
            + b"        if time.monotonic() >= gate_deadline:\n"
            + b"            raise RuntimeError('compiler open gate timed out')\n"
            + b"        time.sleep(0.01)\n"
        )
        call = b"INVOKED_COMPILER = _retain_invoked_compiler()\n"
        instrumented = COMPILER_BYTES.replace(call, gate + call, 1)
        open_boundary = (
            b"                | getattr(os, \"O_CLOEXEC\", 0),\n"
            b"            )\n"
            b"        before = os.fstat(descriptor)\n"
        )
        held_open_boundary = (
            b"                | getattr(os, \"O_CLOEXEC\", 0),\n"
            b"            )\n"
            + f"            Path({str(opened_marker)!r}).write_bytes(b'opened')\n".encode()
            + b"            gate_deadline = time.monotonic() + 10.0\n"
            + f"            while not Path({str(allow_read)!r}).exists():\n".encode()
            + b"                if time.monotonic() >= gate_deadline:\n"
            + b"                    raise RuntimeError('compiler read gate timed out')\n"
            + b"                time.sleep(0.01)\n"
            + b"        before = os.fstat(descriptor)\n"
        )
        instrumented = instrumented.replace(
            open_boundary,
            held_open_boundary,
            1,
        )
        self.assertNotEqual(instrumented, COMPILER_BYTES)
        compiler.write_bytes(instrumented)
        restore = compiler.with_name(".compiler-restore")
        substitute = compiler.with_name(".compiler-substitute")
        restore.write_bytes(instrumented)
        substitute.write_bytes(COMPILER_BYTES)
        process = subprocess.Popen(
            (
                COMPILER.RELEASE_PYTHON_LAUNCHER,
                "-I",
                "-S",
                COMPILER.PRODUCTION_COMPILER_PATH,
                "verify",
                "--repo",
                ".",
            ),
            cwd=self.fixture.root,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 10.0
            while not loaded_marker.exists() and time.monotonic() < deadline:
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            self.assertTrue(loaded_marker.exists())
            os.replace(substitute, compiler)
            allow_open.write_bytes(b"open")
            deadline = time.monotonic() + 10.0
            while not opened_marker.exists() and time.monotonic() < deadline:
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            self.assertTrue(opened_marker.exists())
            os.replace(restore, compiler)
            allow_read.write_bytes(b"read")
            stdout, stderr = process.communicate(timeout=20)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(stdout, "")
        self.assertIn("externally invoked compiler descriptor is invalid", stderr)

    def test_descriptor_split_hostile_worker_cannot_forge_output(self) -> None:
        sentinel = self.fixture.path("hostile-worker-executed")
        hostile_worker = (
            "import hashlib,hmac,json,os,sys\n"
            f"open({str(sentinel)!r},'wb').write(b'executed')\n"
            "control=int(sys.argv[-2]); result=int(sys.argv[-1])\n"
            "def read_exact(fd,size):\n"
            "    payload=b''\n"
            "    while len(payload)<size:\n"
            "        chunk=os.read(fd,size-len(payload))\n"
            "        if not chunk: raise SystemExit(4)\n"
            "        payload+=chunk\n"
            "    return payload\n"
            "size=int.from_bytes(read_exact(control,8),'big')\n"
            "manifest=json.loads(read_exact(control,size))\n"
            "document={'ok':True,'error':None,'result':{\n"
            "    'mode':manifest['mode'],\n"
            f"    'output_path':{COMPILER.EXPECTED_OUTPUT_PATH!r},\n"
            "    'locale_count':1,'key_count':1,\n"
            "    'payload_sha256':'0'*64,'payload_size':1}}\n"
            "body=json.dumps(document,ensure_ascii=True,separators=(',',':'),"
            "allow_nan=False).encode('ascii')\n"
            "nonce=bytes.fromhex(manifest['nonce'])\n"
            "digest=hmac.new(nonce,body,hashlib.sha256).hexdigest().encode('ascii')\n"
            "frame=digest+b'\\n'+body\n"
            "os.write(result,len(frame).to_bytes(8,'big')+frame)\n"
            "raise SystemExit(0 if read_exact(control,1)==b'\\x01' else 3)\n"
        ).encode("ascii")
        self.fixture.write_bytes(COMPILER.PRODUCTION_COMPILER_PATH, hostile_worker)
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()
        completed = subprocess.run(
            (
                COMPILER.RELEASE_PYTHON_LAUNCHER,
                "-I",
                "-S",
                str(COMPILER_PATH),
                "verify",
                "--repo",
                str(self.fixture.root),
            ),
            cwd=REPO_ROOT,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            "repository compiler does not match the externally reviewed compiler bytes",
            completed.stderr,
        )
        self.assertFalse(sentinel.exists())
        self.assertEqual(output.read_bytes(), before)

    def test_preloaded_or_rebound_runtime_state_cannot_emit_authority(self) -> None:
        setups = {
            "preloaded-json": (
                "fake = types.ModuleType('json'); "
                "sys.modules['json'] = fake"
            ),
            "rebound-json": (
                "fake = types.ModuleType('json'); "
                "fake.__dict__.update(json.__dict__); "
                "fake.loads = lambda *a, **k: {}; "
                "sys.modules['json'] = fake"
            ),
            "rebound-os": (
                "fake = types.ModuleType('os'); "
                "fake.__dict__.update(os.__dict__); "
                "fake.open = lambda *a, **k: 0; "
                "sys.modules['os'] = fake"
            ),
            "rebound-ctypes": (
                "fake = types.ModuleType('ctypes'); "
                "fake.__dict__.update(ctypes.__dict__); "
                "fake.CDLL = lambda *a, **k: None; "
                "sys.modules['ctypes'] = fake"
            ),
            "rebound-builtins-import": (
                "original_import = builtins.__import__; "
                "builtins.__import__ = lambda *a, **k: original_import(*a, **k)"
            ),
            "rebound-import-machinery": "sys.meta_path = list(reversed(sys.meta_path))",
        }
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()
        for name, setup in setups.items():
            with self.subTest(name=name):
                wrapper = (
                    "import builtins,ctypes,json,os,runpy,sys,types\n"
                    "path=sys.argv[1]\n"
                    f"{setup}\n"
                    "sys.argv=[path,'verify','--repo','.']\n"
                    "runpy.run_path(path,run_name='__main__')\n"
                )
                completed = subprocess.run(
                    (
                        COMPILER.RELEASE_PYTHON_LAUNCHER,
                        "-I",
                        "-S",
                        "-c",
                        wrapper,
                        COMPILER.PRODUCTION_COMPILER_PATH,
                    ),
                    cwd=self.fixture.root,
                    env={"LC_ALL": "C", "LANG": "C"},
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("compiler_output_verified", completed.stdout)
                self.assertNotIn("compiler_output_created", completed.stdout)
                self.assertEqual(output.read_bytes(), before)


class CurrentRepositoryBoundaryTests(unittest.TestCase):
    def test_honest_current_repo_is_owner_blocked_without_locale_sources(self) -> None:
        locale_directory = REPO_ROOT / COMPILER.EXPECTED_LOCALE_DIRECTORY
        self.assertFalse(locale_directory.exists())
        output = REPO_ROOT / COMPILER.EXPECTED_OUTPUT_PATH
        before = output.read_bytes()
        before_stat = output.stat()
        completed = subprocess.run(
            (
                COMPILER.RELEASE_PYTHON_LAUNCHER,
                "-I",
                "-S",
                COMPILER.PRODUCTION_COMPILER_PATH,
                "verify",
                "--repo",
                ".",
            ),
            cwd=REPO_ROOT,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            "OWNER-BLOCKED: localization/website/locales is absent",
            completed.stderr,
        )
        self.assertNotIn("binding mismatch", completed.stderr)
        self.assertNotIn("descriptor-bound source bytes", completed.stderr)
        self.assertEqual(output.read_bytes(), before)
        after_stat = output.stat()
        self.assertEqual(after_stat.st_ino, before_stat.st_ino)
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)


class FilesystemBoundaryTests(CompilerTestCase):
    def test_symlinked_repository_root_is_rejected(self) -> None:
        container = tempfile.TemporaryDirectory()
        self.addCleanup(container.cleanup)
        link = Path(container.name) / "repo-link"
        link.symlink_to(self.fixture.root, target_is_directory=True)
        with self.assertCompilerError("root or ancestor is unsafe"):
            COMPILER._compile_repository_with_binding(
                link,
                mode="verify",
                binding=self.fixture.binding,
            )

    def test_repository_root_swap_restore_is_detected_by_ancestor_custody(self) -> None:
        original = COMPILER._build_compiler_output
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()

        def swap_root(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            held = self.fixture.root.with_name("repo-held")
            self.fixture.root.rename(held)
            self.fixture.root.mkdir()
            self.fixture.root.rmdir()
            held.rename(self.fixture.root)
            return result

        with mock.patch.object(
            COMPILER,
            "_build_compiler_output",
            side_effect=swap_root,
        ):
            with self.assertCompilerError("repository ancestor changed"):
                self.fixture.compile("verify")
        self.assertEqual(output.read_bytes(), before)

    def test_unrelated_shared_ancestor_churn_does_not_break_custody(self) -> None:
        original = COMPILER._build_compiler_output
        sibling = self.fixture.root.parent / "unrelated-sibling"

        def create_unrelated_sibling(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            sibling.write_bytes(b"unrelated\n")
            return result

        try:
            with mock.patch.object(
                COMPILER,
                "_build_compiler_output",
                side_effect=create_unrelated_sibling,
            ):
                result = self.fixture.compile("verify")
            self.assertEqual(result.mode, "verify")
        finally:
            sibling.unlink(missing_ok=True)

    def test_inventory_addition_after_listdir_is_detected(self) -> None:
        real_listdir = COMPILER.os.listdir
        extra = self.fixture.path(
            f"{COMPILER.EXPECTED_LOCALE_DIRECTORY}/late-addition.json"
        )
        injected = False

        def add_after_listdir(directory_fd: int) -> list[str]:
            nonlocal injected
            names = real_listdir(directory_fd)
            if not injected:
                injected = True
                extra.write_bytes(b"{}\n")
            return names

        try:
            with mock.patch.object(
                COMPILER.os,
                "listdir",
                side_effect=add_after_listdir,
            ):
                with self.assertCompilerError("inventory changed while listed"):
                    self.fixture.compile("verify")
        finally:
            if extra.exists():
                extra.unlink()

    def test_inventory_removal_after_listdir_is_detected(self) -> None:
        real_listdir = COMPILER.os.listdir
        locale_code = self.fixture.target_locales[0]
        locale = self.fixture.locale_path(locale_code)
        payload = locale.read_bytes()
        injected = False

        def remove_after_listdir(directory_fd: int) -> list[str]:
            nonlocal injected
            names = real_listdir(directory_fd)
            if not injected:
                injected = True
                locale.unlink()
            return names

        try:
            with mock.patch.object(
                COMPILER.os,
                "listdir",
                side_effect=remove_after_listdir,
            ):
                with self.assertCompilerError("inventory changed while listed"):
                    self.fixture.compile("verify")
        finally:
            if not locale.exists():
                locale.write_bytes(payload)

    def test_fifo_locale_is_rejected_without_blocking_public_boundary(self) -> None:
        locale = self.fixture.locale_path(self.fixture.target_locales[0])
        locale.unlink()
        os.mkfifo(locale, 0o600)
        started = time.monotonic()
        completed = self.fixture.public_compile("verify", timeout=5)
        elapsed = time.monotonic() - started
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("compiler_output_verified", completed.stdout)
        self.assertIn("file identity is unsafe", completed.stderr)
        self.assertLess(elapsed, 5.0)

    def test_symlinked_locale_directory_is_rejected(self) -> None:
        locale_directory = self.fixture.path(COMPILER.EXPECTED_LOCALE_DIRECTORY)
        held = locale_directory.with_name("locales-held")
        locale_directory.rename(held)
        locale_directory.symlink_to(held, target_is_directory=True)
        with self.assertCompilerError("directory is unsafe or unavailable"):
            self.fixture.compile("verify")

    def test_symlinked_locale_file_is_rejected(self) -> None:
        locale = self.fixture.locale_path("fr")
        held = self.fixture.path("fr-held.json")
        locale.rename(held)
        locale.symlink_to(held)
        with self.assertCompilerError("file is unsafe or unavailable"):
            self.fixture.compile("verify")

    def test_hardlinked_locale_file_is_rejected(self) -> None:
        locale = self.fixture.locale_path("fr")
        hardlink = self.fixture.path("fr-hardlink.json")
        os.link(locale, hardlink)
        with self.assertCompilerError("file identity is unsafe"):
            self.fixture.compile("verify")

    def test_symlinked_and_hardlinked_output_are_rejected(self) -> None:
        symlink_fixture = RepositoryFixture(self)
        symlink_output = symlink_fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        symlink_held = symlink_output.with_name("major-held.json")
        symlink_output.rename(symlink_held)
        symlink_output.symlink_to(symlink_held)
        with self.assertRaisesRegex(
            COMPILER.WebsiteTranslationCompilerError,
            "file is unsafe or unavailable",
        ):
            symlink_fixture.compile("verify")

        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        os.link(output, self.fixture.path("major-hardlink.json"))
        with self.assertCompilerError("file identity is unsafe"):
            self.fixture.compile("verify")

    def test_locale_path_substitution_after_validation_is_rejected(self) -> None:
        original = COMPILER._build_compiler_output

        def substitute(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            replacement_document = copy.deepcopy(
                self.fixture.locale_documents["fr"]
            )
            key = self.fixture.keys[0]
            replacement_document["translations"][key] = "Substituted value"
            replacement = self.fixture.locale_path("fr").with_name(".replacement")
            replacement.write_bytes(
                VALIDATOR.canonical_json_bytes(
                    replacement_document,
                    ensure_ascii=False,
                )
            )
            os.replace(replacement, self.fixture.locale_path("fr"))
            return result

        with mock.patch.object(
            COMPILER,
            "_build_compiler_output",
            side_effect=substitute,
        ):
            with self.assertCompilerError("inventory changed|file changed"):
                self.fixture.compile("verify")

    def test_locale_in_place_mutation_after_validation_is_rejected(self) -> None:
        original = COMPILER._build_compiler_output

        def mutate(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            locale = self.fixture.locale_path("fr")
            locale.write_bytes(locale.read_bytes() + b" ")
            return result

        with mock.patch.object(
            COMPILER,
            "_build_compiler_output",
            side_effect=mutate,
        ):
            with self.assertCompilerError("file changed during compilation"):
                self.fixture.compile("verify")

    def test_locale_parent_directory_substitution_is_rejected(self) -> None:
        original = COMPILER._build_compiler_output

        def substitute_parent(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            locale_directory = self.fixture.path(COMPILER.EXPECTED_LOCALE_DIRECTORY)
            held = locale_directory.with_name("locales-original")
            locale_directory.rename(held)
            locale_directory.mkdir()
            return result

        with mock.patch.object(
            COMPILER,
            "_build_compiler_output",
            side_effect=substitute_parent,
        ):
            with self.assertCompilerError("directory changed during compilation"):
                self.fixture.compile("verify")

    def test_parent_swap_restore_cannot_inject_substitute_locale_bytes(self) -> None:
        original = COMPILER._build_compiler_output
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()

        def swap_restore(*args: object, **kwargs: object) -> object:
            locale_directory = self.fixture.path(COMPILER.EXPECTED_LOCALE_DIRECTORY)
            held = locale_directory.with_name("locales-bound-original")
            locale_directory.rename(held)
            locale_directory.mkdir()
            try:
                return original(*args, **kwargs)
            finally:
                locale_directory.rmdir()
                held.rename(locale_directory)

        with mock.patch.object(
            COMPILER,
            "_build_compiler_output",
            side_effect=swap_restore,
        ):
            with self.assertCompilerError("inventory changed"):
                self.fixture.compile("verify")
        self.assertEqual(output.read_bytes(), before)


class OutputPublicationTests(CompilerTestCase):
    def test_create_refuses_existing_output_without_mutation(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()
        before_metadata = output.stat()
        with self.assertCompilerError("refuses to overwrite existing"):
            self.fixture.compile("create")
        after_metadata = output.stat()
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(after_metadata.st_ino, before_metadata.st_ino)
        self.assertEqual(after_metadata.st_mtime_ns, before_metadata.st_mtime_ns)

    def test_temporary_name_collision_preserves_collision(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        collision_name = ".major.json.compile.collision"
        collision = output.parent / collision_name
        collision.write_bytes(b"do-not-touch")
        with mock.patch.object(
            COMPILER,
            "_new_private_basename",
            return_value=collision_name,
        ):
            with self.assertCompilerError("temporary name collided"):
                self.fixture.compile("create")
        self.assertFalse(output.exists())
        self.assertEqual(collision.read_bytes(), b"do-not-touch")

    def test_temporary_path_escape_is_rejected(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        escaped = output.parent.parent / "escaped.json"
        with mock.patch.object(
            COMPILER,
            "_new_private_basename",
            return_value="../escaped.json",
        ):
            with self.assertCompilerError("temporary output name is unsafe"):
                self.fixture.compile("create")
        self.assertFalse(output.exists())
        self.assertFalse(escaped.exists())

    def test_verify_rejects_wrong_output_without_rewriting_it(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        wrong = b"{}\n"
        output.write_bytes(wrong)
        with self.assertCompilerError("locale order|does not match"):
            self.fixture.compile("verify")
        self.assertEqual(output.read_bytes(), wrong)

    def test_verify_detects_output_path_substitution(self) -> None:
        original = COMPILER._canonical_output_bytes
        calls = 0

        def substitute_on_verification(validator: object, document: object) -> bytes:
            nonlocal calls
            calls += 1
            payload = original(validator, document)
            if calls == 3:
                output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
                replacement = output.with_name(".major-substitute")
                replacement.write_bytes(b"{}\n")
                os.replace(replacement, output)
            return payload

        with mock.patch.object(
            COMPILER,
            "_canonical_output_bytes",
            side_effect=substitute_on_verification,
        ):
            with self.assertCompilerError("file changed during compilation"):
                self.fixture.compile("verify")

    def test_post_stat_output_swap_restore_is_rejected(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        before = output.read_bytes()
        real_stat = COMPILER.os.stat
        swapped = False

        def swap_after_stat(path: object, *args: object, **kwargs: object):
            nonlocal swapped
            metadata = real_stat(path, *args, **kwargs)
            if path == output.name and not swapped:
                swapped = True
                held = output.with_name(".major-post-stat-held")
                replacement = output.with_name(".major-post-stat-replacement")
                output.rename(held)
                replacement.write_bytes(b"{}\n")
                os.replace(replacement, output)
                output.unlink()
                held.rename(output)
            return metadata

        with mock.patch.object(COMPILER.os, "stat", side_effect=swap_after_stat):
            with self.assertCompilerError("file changed while read"):
                self.fixture.compile("verify")
        self.assertTrue(swapped)
        self.assertEqual(output.read_bytes(), before)

    def test_same_inode_output_mutation_before_success_is_rejected(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        original = COMPILER._assert_retained_output_exact

        def mutate_same_inode(
            secure: object,
            directory_fd: int,
            name: str,
            fd: int,
            identity: tuple[int, int],
            payload: bytes,
        ) -> None:
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"{}\n")
            os.fsync(fd)
            original(secure, directory_fd, name, fd, identity, payload)

        with mock.patch.object(
            COMPILER,
            "_assert_retained_output_exact",
            side_effect=mutate_same_inode,
        ):
            with self.assertCompilerError("published compiler output"):
                self.fixture.compile("create")
        self.assertFalse(output.exists())

    def test_cleanup_substitution_preserves_replacement(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        original = COMPILER._write_all
        attacker = b"attacker-owned-temporary\n"
        substituted_name: Path | None = None

        def substitute_before_failure(fd: int, payload: bytes) -> None:
            nonlocal substituted_name
            original(fd, payload)
            candidates = list(output.parent.glob(".major.json.compile.*"))
            self.assertEqual(len(candidates), 1)
            temporary = candidates[0]
            held = output.parent / ".owned-compiler-temporary-held"
            temporary.rename(held)
            temporary.write_bytes(attacker)
            substituted_name = temporary
            raise COMPILER.WebsiteTranslationCompilerError(
                "injected write validation failure"
            )

        with mock.patch.object(
            COMPILER,
            "_write_all",
            side_effect=substitute_before_failure,
        ):
            with self.assertCompilerError("cleanup substitution was preserved"):
                self.fixture.compile("create")
        self.assertIsNotNone(substituted_name)
        self.assertEqual(substituted_name.read_bytes(), attacker)
        self.assertFalse(output.exists())

    def test_failure_before_temporary_identity_assignment_is_cleaned(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        real_open = COMPILER.os.open
        real_fstat = COMPILER.os.fstat
        temporary_fd: int | None = None
        injected = False

        def track_temporary_open(
            path: object,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            nonlocal temporary_fd
            fd = real_open(path, flags, *args, **kwargs)
            if (
                isinstance(path, str)
                and path.startswith(".major.json.compile.")
                and flags & os.O_CREAT
            ):
                temporary_fd = fd
            return fd

        def fail_first_temporary_fstat(fd: int):
            nonlocal injected
            if fd == temporary_fd and not injected:
                injected = True
                raise OSError(5, "injected pre-identity fstat failure")
            return real_fstat(fd)

        with mock.patch.object(
            COMPILER.os,
            "open",
            side_effect=track_temporary_open,
        ), mock.patch.object(
            COMPILER.os,
            "fstat",
            side_effect=fail_first_temporary_fstat,
        ):
            with self.assertCompilerError("compiler filesystem operation failed"):
                self.fixture.compile("create")
        self.assertTrue(injected)
        self.assertFalse(output.exists())
        self.assertEqual(
            list(output.parent.glob(".major.json.compile.*")),
            [],
        )
        self.assertEqual(
            list(output.parent.glob(".major.json.cleanup.*")),
            [],
        )

    def test_unsupported_platform_fails_before_creating_a_temporary(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        with mock.patch.object(COMPILER.sys, "platform", "linux"):
            with self.assertCompilerError("unsupported on this platform"):
                self.fixture.compile("create")
        self.assertFalse(output.exists())
        self.assertEqual(
            list(output.parent.glob(".major.json.compile.*")),
            [],
        )

    def test_create_detects_output_substitution_after_exclusive_rename(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        real_rename = COMPILER._rename_exclusive
        rename_calls = 0

        def substitute_after_rename(*args: object, **kwargs: object) -> None:
            nonlocal rename_calls
            rename_calls += 1
            real_rename(*args, **kwargs)
            if rename_calls == 1:
                replacement = output.with_name(".major-published-substitute")
                replacement.write_bytes(b"{}\n")
                os.replace(replacement, output)

        with mock.patch.object(
            COMPILER,
            "_rename_exclusive",
            side_effect=substitute_after_rename,
        ):
            with self.assertCompilerError("cleanup substitution was preserved"):
                self.fixture.compile("create")
        self.assertEqual(output.read_bytes(), b"{}\n")

    def test_failed_post_publish_stability_check_removes_owned_output(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        real_rename = COMPILER._rename_exclusive

        def mutate_input_after_rename(*args: object, **kwargs: object) -> None:
            real_rename(*args, **kwargs)
            locale = self.fixture.locale_path("fr")
            locale.write_bytes(locale.read_bytes() + b" ")

        with mock.patch.object(
            COMPILER,
            "_rename_exclusive",
            side_effect=mutate_input_after_rename,
        ):
            with self.assertCompilerError("file changed during compilation"):
                self.fixture.compile("create")
        self.assertFalse(output.exists())

    def test_destination_created_at_publish_boundary_is_not_overwritten(self) -> None:
        output = self.fixture.path(COMPILER.EXPECTED_OUTPUT_PATH)
        output.unlink()
        attacker = b"attacker-owned-output\n"
        real_rename = COMPILER._rename_exclusive

        def create_destination_then_rename(*args: object, **kwargs: object) -> None:
            output.write_bytes(attacker)
            real_rename(*args, **kwargs)

        with mock.patch.object(
            COMPILER,
            "_rename_exclusive",
            side_effect=create_destination_then_rename,
        ):
            with self.assertCompilerError("refuses to overwrite existing"):
                self.fixture.compile("create")
        self.assertEqual(output.read_bytes(), attacker)


if __name__ == "__main__":
    unittest.main()
