#!/usr/bin/env python3
"""Focused tests for the website localization contract boundary."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("website_localization_contract.py")
REPO_ROOT = MODULE_PATH.parent.parent
SPEC = importlib.util.spec_from_file_location(
    "website_localization_contract_under_test",
    MODULE_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load website_localization_contract.py")
CONTRACT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTRACT
SPEC.loader.exec_module(CONTRACT)


class RepositoryFixture:
    def __init__(self, owner: unittest.TestCase) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        owner.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.body = (
            '<main><p>Hello</p><input placeholder="Email">'
            '<section translate="no"><p>Do not translate</p></section></main>'
        )
        self.runtime_nontranslatable = ["Never shown"]
        self.audit_nontranslatable = ["Never shown"]
        self.languages: list[dict[str, object]] = [
            {"code": "en", "name": "English", "instant": True},
            {"code": "fr", "name": "French", "instant": True},
            {"code": "de", "name": "German", "instant": False},
        ]
        self.major: dict[str, dict[str, str]] = {"en": {}, "fr": {}}
        self.write_sources()
        self.write_contract()

    def path(self, relative: str) -> Path:
        return self.root / relative

    def write_bytes(self, relative: str, payload: bytes) -> None:
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def write_text(self, relative: str, payload: str) -> None:
        self.write_bytes(relative, payload.encode("utf-8"))

    def write_json(self, relative: str, document: object) -> None:
        self.write_bytes(
            relative,
            CONTRACT.canonical_json_bytes(document, ensure_ascii=False),
        )

    def write_sources(self) -> None:
        runtime = json.dumps(self.runtime_nontranslatable, ensure_ascii=False)
        self.write_text(
            CONTRACT.INDEX_PATH,
            f"<!doctype html><html><body>{self.body}"
            f"<script>const nonTranslatableKeys = new Set({runtime});</script>"
            "</body></html>\n",
        )
        audit_values = ", ".join(repr(value) for value in self.audit_nontranslatable)
        self.write_text(
            CONTRACT.AUDIT_PATH,
            f"NON_TRANSLATABLE_KEYS = {{{audit_values}}}\n",
        )
        self.write_json(CONTRACT.LANGUAGES_PATH, self.languages)
        self.write_json(CONTRACT.AGGREGATE_PATH, self.major)

    def write_contract(self) -> dict[str, object]:
        document = CONTRACT.build_expected_contract(self.root)
        self.write_bytes(
            CONTRACT.DEFAULT_CONTRACT_PATH,
            CONTRACT.canonical_json_bytes(document, ensure_ascii=True),
        )
        return document

    def contract(self) -> dict[str, object]:
        return CONTRACT.load_validated_contract(self.root)

    def locale_document(
        self,
        contract: dict[str, object],
        *,
        locale: str = "fr",
    ) -> dict[str, object]:
        keys = contract["key_classification"]["translatable_static_keys"]
        return {
            "schema": CONTRACT.LOCALE_SOURCE_SCHEMA,
            "locale": locale,
            "english_source_identity_sha256": contract["english_source"][
                "identity_sha256"
            ],
            "instant_locale_inventory_sha256": contract[
                "instant_locale_inventory"
            ]["identity_sha256"],
            "translatable_static_keys_sha256": contract["key_classification"][
                "translatable_static_keys_sha256"
            ],
            "translations": {key: f"FR: {key}" for key in keys},
        }


class StrictJsonTests(unittest.TestCase):
    def test_strict_json_accepts_nested_finite_content(self) -> None:
        self.assertEqual(
            CONTRACT.strict_json_loads(
                b'{"outer":{"items":[1,2.5,"ok"]}}',
                label="test JSON",
            ),
            {"outer": {"items": [1, 2.5, "ok"]}},
        )

    def test_malformed_json_is_rejected(self) -> None:
        for payload in (b"not-json", b'{"x":', b'{"x":1,}', b"[] trailing"):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "malformed test JSON",
                ):
                    CONTRACT.strict_json_loads(payload, label="test JSON")

    def test_duplicate_keys_are_rejected_at_every_depth(self) -> None:
        payloads = (
            b'{"locale":{},"locale":{}}',
            b'{"locale":{"Hello":"one","Hello":"two"}}',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "duplicate JSON key",
                ):
                    CONTRACT.strict_json_loads(payload, label="test JSON")

    def test_nonfinite_values_are_rejected_at_nested_positions(self) -> None:
        for value in ("NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(value=value):
                payload = f'{{"outer":{{"value":{value}}}}}'.encode("ascii")
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "non-finite JSON value",
                ):
                    CONTRACT.strict_json_loads(payload, label="test JSON")

    def test_bom_invalid_utf8_and_surrogates_are_rejected(self) -> None:
        hostile = (
            b"\xef\xbb\xbf{}",
            b'{"x":"\xff"}',
            b'{"x":"\\ud800"}',
        )
        for payload in hostile:
            with self.subTest(payload=payload):
                with self.assertRaises(CONTRACT.WebsiteLocalizationContractError):
                    CONTRACT.strict_json_loads(payload, label="test JSON")


class StaticKeyExtractionTests(unittest.TestCase):
    def test_translate_no_is_inherited_by_text_and_attributes(self) -> None:
        payload = b"""
        <main>
          <p>Visible text</p>
          <input placeholder="Visible attribute">
          <section translate="no" aria-label="Excluded parent attribute">
            <p>Excluded text <span>Excluded nested text</span></p>
            <img alt="Excluded nested attribute">
            <div translate="yes">Still excluded by ancestor</div>
          </section>
          <p>Shared</p><div translate="no"><span>Shared</span></div>
          <script>Script text</script><style>Style text</style>
        </main>
        """
        translatable, excluded = CONTRACT.extract_static_keys(payload)
        self.assertEqual(
            translatable,
            {"Shared", "Visible attribute", "Visible text"},
        )
        self.assertEqual(
            excluded,
            {
                "Excluded nested attribute",
                "Excluded nested text",
                "Excluded parent attribute",
                "Excluded text",
                "Shared",
                "Still excluded by ancestor",
            },
        )

    def test_static_key_whitespace_is_canonicalized(self) -> None:
        translatable, excluded = CONTRACT.extract_static_keys(
            b'<main><p>  Hello\n world </p><div translate="no"> A\t B </div></main>'
        )
        self.assertEqual(translatable, {"Hello world"})
        self.assertEqual(excluded, {"A B"})


class ContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepositoryFixture(self)

    def test_fixture_contract_validates_without_claiming_content_readiness(self) -> None:
        contract = self.fixture.contract()
        self.assertEqual(
            contract["compiler_output"]["locale_order"],
            ["en", "fr"],
        )
        output = io.StringIO()
        with redirect_stdout(output):
            result = CONTRACT.main(
                ["validate-contract", "--repo", str(self.fixture.root)]
            )
        self.assertEqual(result, 0)
        self.assertIn("locale_sources=not_checked", output.getvalue())
        self.assertIn("translation_readiness=not_checked", output.getvalue())

    def test_english_source_drift_invalidates_the_contract(self) -> None:
        index = self.fixture.path(CONTRACT.INDEX_PATH)
        index.write_text(
            index.read_text(encoding="utf-8").replace("<p>Hello</p>", "<p>Changed</p>"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            r"english_source\.file_sha256",
        ):
            CONTRACT.load_validated_contract(self.fixture.root)

    def test_path_escape_and_noncanonical_paths_are_rejected(self) -> None:
        contract = CONTRACT.build_expected_contract(self.fixture.root)
        hostile = (
            "../web/index.html",
            "/web/index.html",
            "web\\index.html",
            "web//index.html",
            "web/./index.html",
        )
        for path in hostile:
            with self.subTest(path=path):
                changed = copy.deepcopy(contract)
                changed["english_source"]["path"] = path
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "safe relative path|authoritative",
                ):
                    CONTRACT.validate_contract_document(changed)

    def test_duplicate_instant_locale_is_rejected(self) -> None:
        contract = CONTRACT.build_expected_contract(self.fixture.root)
        contract["instant_locale_inventory"]["locales"].append(
            {"code": "fr", "name": "French duplicate"}
        )
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "unique English|locale-source targets",
        ):
            CONTRACT.validate_contract_document(contract)

    def test_source_inventory_duplicate_locale_fails_closed(self) -> None:
        self.fixture.languages.append(
            {"code": "fr", "name": "French duplicate", "instant": False}
        )
        self.fixture.write_json(CONTRACT.LANGUAGES_PATH, self.fixture.languages)
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "duplicate locale inventory code: fr",
        ):
            CONTRACT.build_expected_contract(self.fixture.root)

    def test_unsupported_instant_locale_syntax_is_rejected(self) -> None:
        self.fixture.languages[1]["code"] = "../fr"
        self.fixture.major = {"en": {}, "../fr": {}}
        self.fixture.write_sources()
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "unsupported instant locale syntax",
        ):
            CONTRACT.build_expected_contract(self.fixture.root)

    def test_key_arrays_require_deterministic_order(self) -> None:
        contract = CONTRACT.build_expected_contract(self.fixture.root)
        keys = contract["key_classification"]["translatable_static_keys"]
        self.assertGreaterEqual(len(keys), 2)
        contract["key_classification"]["translatable_static_keys"] = list(
            reversed(keys)
        )
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "must be sorted",
        ):
            CONTRACT.validate_contract_document(contract)

    def test_contract_object_key_order_is_exact(self) -> None:
        contract = CONTRACT.build_expected_contract(self.fixture.root)
        reordered = {"english_source": contract["english_source"]}
        reordered.update(
            (key, value) for key, value in contract.items() if key != "english_source"
        )
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "keys or key order are invalid",
        ):
            CONTRACT.validate_contract_document(reordered)

    def test_serialization_schema_rejects_json_type_aliases(self) -> None:
        for field, value in (("indent", 2.0), ("ensure_ascii", 0)):
            with self.subTest(field=field, value=value):
                contract = CONTRACT.build_expected_contract(self.fixture.root)
                contract["locale_sources"]["serialization"][field] = value
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "not the required format",
                ):
                    CONTRACT.validate_contract_document(contract)

    def test_contract_file_requires_canonical_ascii_lf_json(self) -> None:
        path = self.fixture.path(CONTRACT.DEFAULT_CONTRACT_PATH)
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "canonical ASCII/LF order",
        ):
            CONTRACT.load_validated_contract(self.fixture.root)

    def test_symlinked_repository_file_is_rejected(self) -> None:
        target = self.fixture.root / "outside-index.html"
        target.write_text("outside", encoding="utf-8")
        index = self.fixture.path(CONTRACT.INDEX_PATH)
        index.unlink()
        index.symlink_to(target)
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "unsafe or unavailable repository file",
        ):
            CONTRACT.build_expected_contract(self.fixture.root)


class LocaleSourceValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepositoryFixture(self)
        self.contract = self.fixture.contract()

    def test_complete_bound_locale_source_validates(self) -> None:
        source = self.fixture.locale_document(self.contract)
        self.assertIs(
            CONTRACT.validate_locale_document(
                source,
                expected_locale="fr",
                contract=self.contract,
            ),
            source,
        )

    def test_unsupported_and_english_locale_sources_are_rejected(self) -> None:
        for locale in ("en", "es", "../fr", "fr-FR"):
            with self.subTest(locale=locale):
                source = self.fixture.locale_document(self.contract, locale=locale)
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "unsupported locale source",
                ):
                    CONTRACT.validate_locale_document(
                        source,
                        expected_locale=locale,
                        contract=self.contract,
                    )

    def test_locale_identity_and_hash_binding_drift_are_rejected(self) -> None:
        source = self.fixture.locale_document(self.contract)
        source["locale"] = "de"
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "identity mismatch",
        ):
            CONTRACT.validate_locale_document(
                source,
                expected_locale="fr",
                contract=self.contract,
            )
        source = self.fixture.locale_document(self.contract)
        source["english_source_identity_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "binding drift",
        ):
            CONTRACT.validate_locale_document(
                source,
                expected_locale="fr",
                contract=self.contract,
            )

    def test_missing_extra_and_reordered_translation_keys_are_rejected(self) -> None:
        valid = self.fixture.locale_document(self.contract)
        variants: list[dict[str, object]] = []
        missing = copy.deepcopy(valid)
        missing["translations"].pop(next(iter(missing["translations"])))
        variants.append(missing)
        extra = copy.deepcopy(valid)
        extra["translations"]["Unexpected"] = "Inattendu"
        variants.append(extra)
        reordered = copy.deepcopy(valid)
        reordered["translations"] = dict(
            reversed(list(reordered["translations"].items()))
        )
        variants.append(reordered)
        for source in variants:
            with self.subTest(keys=list(source["translations"])):
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "translation keys or order differ",
                ):
                    CONTRACT.validate_locale_document(
                        source,
                        expected_locale="fr",
                        contract=self.contract,
                    )

    def test_empty_untrimmed_and_english_fallback_values_are_rejected(self) -> None:
        valid = self.fixture.locale_document(self.contract)
        first = next(iter(valid["translations"]))
        for value in ("", "   ", " translation", "translation ", first, 7, None):
            with self.subTest(value=value):
                source = copy.deepcopy(valid)
                source["translations"][first] = value
                with self.assertRaisesRegex(
                    CONTRACT.WebsiteLocalizationContractError,
                    "not translation-ready",
                ):
                    CONTRACT.validate_locale_document(
                        source,
                        expected_locale="fr",
                        contract=self.contract,
                    )

    def test_locale_source_file_requires_exact_path_and_canonical_json(self) -> None:
        source = self.fixture.locale_document(self.contract)
        path = self.fixture.path("localization/website/locales/fr.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(CONTRACT.canonical_json_bytes(source, ensure_ascii=False))
        self.assertEqual(
            CONTRACT.load_validated_locale_source(
                self.fixture.root,
                locale="fr",
                contract=self.contract,
            ),
            source,
        )
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "not canonical UTF-8/LF JSON",
        ):
            CONTRACT.load_validated_locale_source(
                self.fixture.root,
                locale="fr",
                contract=self.contract,
            )

    def test_symlinked_locale_directory_cannot_escape(self) -> None:
        outside = self.fixture.root / "outside-locales"
        outside.mkdir()
        source = self.fixture.locale_document(self.contract)
        (outside / "fr.json").write_bytes(
            CONTRACT.canonical_json_bytes(source, ensure_ascii=False)
        )
        website = self.fixture.path("localization/website")
        (website / "locales").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "unsafe or unavailable repository file",
        ):
            CONTRACT.load_validated_locale_source(
                self.fixture.root,
                locale="fr",
                contract=self.contract,
            )

    def test_compiler_output_requires_exact_locale_and_key_order(self) -> None:
        source = self.fixture.locale_document(self.contract)
        keys = self.contract["key_classification"]["translatable_static_keys"]
        honest = {
            "en": {key: key for key in keys},
            "fr": dict(source["translations"]),
        }
        self.assertEqual(
            CONTRACT.validate_compiler_output_document(
                honest,
                contract=self.contract,
                locale_sources={"fr": source},
            ),
            honest,
        )
        wrong_locale_order = {"fr": honest["fr"], "en": honest["en"]}
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "locale order",
        ):
            CONTRACT.validate_compiler_output_document(
                wrong_locale_order,
                contract=self.contract,
                locale_sources={"fr": source},
            )
        wrong_key_order = copy.deepcopy(honest)
        wrong_key_order["fr"] = dict(reversed(list(honest["fr"].items())))
        with self.assertRaisesRegex(
            CONTRACT.WebsiteLocalizationContractError,
            "key order",
        ):
            CONTRACT.validate_compiler_output_document(
                wrong_key_order,
                contract=self.contract,
                locale_sources={"fr": source},
            )


class CurrentTreeContractTests(unittest.TestCase):
    def test_current_tree_contract_validation(self) -> None:
        contract = CONTRACT.load_validated_contract(REPO_ROOT)
        classification = contract["key_classification"]
        self.assertEqual(len(classification["translatable_static_keys"]), 379)
        self.assertEqual(len(classification["nontranslatable_static_keys"]), 37)
        self.assertEqual(
            len(classification["inherited_translate_no_only_keys"]),
            83,
        )
        self.assertEqual(len(classification["mixed_translate_context_keys"]), 4)
        self.assertEqual(
            len(contract["instant_locale_inventory"]["locales"]),
            39,
        )

    def test_current_four_drift_keys_are_classified_nontranslatable(self) -> None:
        contract = CONTRACT.load_validated_contract(REPO_ROOT)
        classification = contract["key_classification"]
        expected = [
            "Affordable Yet Great Product!",
            "Win's VPN",
            "Winn Protocol\u2122",
            "apps.irs.gov/app/eos",
        ]
        drift = classification["runtime_audit_nontranslatable_drift"]
        self.assertEqual(drift["classification"], "nontranslatable")
        self.assertEqual(drift["keys"], expected)
        self.assertTrue(
            set(expected).issubset(classification["nontranslatable_static_keys"])
        )

    def test_current_translation_readiness_remains_failure(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "audit_website_translations.py"),
                "--show",
                "0",
            ],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("visible_keys=499 languages=39", completed.stdout)
        self.assertRegex(completed.stdout, r"(?m)^fr: untranslated=[1-9][0-9]*")


if __name__ == "__main__":
    unittest.main()
