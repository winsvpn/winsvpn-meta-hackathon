#!/usr/bin/env python3
"""Focused tests for contract-bound website locale-source filling."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import fill_website_translations as fill
import website_localization_contract as contract_tool
from fill_website_translations import (
    protect_literals,
    restore_literals,
    sanitize_translation_placeholders,
)


def complete_provider(
    provider: str,
    api_key: str | None,
    target: str,
    strings: list[str],
    delay: float,
) -> dict[str, str]:
    del provider, api_key, delay
    prefix = "HE" if target == "he" else target.upper()
    return {source: f"{prefix}: {source}" for source in strings}


class RepositoryFixture:
    def __init__(self, owner: unittest.TestCase) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        owner.addCleanup(self._temporary.cleanup)
        self.root = pathlib.Path(self._temporary.name)
        self.index = self.root / contract_tool.INDEX_PATH
        self.audit = self.root / contract_tool.AUDIT_PATH
        self.languages_path = self.root / contract_tool.LANGUAGES_PATH
        self.major_path = self.root / contract_tool.AGGREGATE_PATH
        self.contract_path = self.root / contract_tool.DEFAULT_CONTRACT_PATH
        self.validator_path = self.root / fill.ACCEPTED_VALIDATOR_PATH
        self.locale_directory = self.root / fill.ACCEPTED_LOCALE_DIRECTORY
        self.locale_path = self.locale_directory / "fr.json"
        self.languages = [
            {"code": "en", "name": "English", "instant": True},
            {"code": "fr", "name": "French", "instant": True},
            {"code": "de", "name": "German", "instant": True},
        ]
        self.major: dict[str, dict[str, str]] = {
            "en": {},
            "fr": {"Hello": "Bonjour", "Email": "Email"},
            "de": {},
        }
        self._write_sources()
        self.contract = self._write_contract()
        self.key_count = len(
            self.contract["key_classification"]["translatable_static_keys"]
        )
        self.contract_sha256 = hashlib.sha256(
            self.contract_path.read_bytes()
        ).hexdigest()
        self.validator_sha256 = hashlib.sha256(
            self.validator_path.read_bytes()
        ).hexdigest()

    @staticmethod
    def _canonical(document: object, *, ensure_ascii: bool = False) -> bytes:
        return (
            json.dumps(
                document,
                ensure_ascii=ensure_ascii,
                allow_nan=False,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")

    def _write(self, path: pathlib.Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def _write_sources(self) -> None:
        index_payload = (
            '<main><p>Hello</p><input placeholder="Email">'
            '<section translate="no"><p>Never shown</p></section></main>'
            '<script>const nonTranslatableKeys = new Set(["Never shown"]);</script>'
        ).encode("utf-8")
        self._write(self.index, index_payload)
        self._write(
            self.audit,
            b'NON_TRANSLATABLE_KEYS = {"Never shown"}\n',
        )
        self._write(self.languages_path, self._canonical(self.languages))
        self._write(self.major_path, self._canonical(self.major))
        self._write(
            self.validator_path,
            pathlib.Path(contract_tool.__file__).read_bytes(),
        )
        self.locale_directory.mkdir(parents=True, exist_ok=True)

    def _write_contract(self) -> dict[str, object]:
        document = contract_tool.build_expected_contract(self.root)
        self._write(
            self.contract_path,
            contract_tool.canonical_json_bytes(document, ensure_ascii=True),
        )
        return document

    def invoke(
        self,
        mode: str,
        *,
        locales: list[str] | None = None,
        refresh_keys: list[str] | None = None,
        provider: str = "official",
        api_key: str | None = "temporary-test-key",
        delay: float = 0,
        contract_sha256: str | None = None,
        validator_sha256: str | None = None,
    ) -> fill.FillResult:
        with (
            mock.patch.object(
                fill,
                "ACCEPTED_CONTRACT_SHA256",
                contract_sha256 or self.contract_sha256,
            ),
            mock.patch.object(
                fill,
                "ACCEPTED_VALIDATOR_SHA256",
                validator_sha256 or self.validator_sha256,
            ),
            mock.patch.object(
                fill,
                "EXPECTED_TRANSLATABLE_KEY_COUNT",
                self.key_count,
            ),
        ):
            return fill._run_operation(
                self.root,
                mode=mode,
                requested_locales=locales or ["fr"],
                refresh_keys=refresh_keys or [],
                provider=provider,
                api_key=api_key,
                delay=delay,
            )


class TransportAndPlaceholderTests(unittest.TestCase):
    def test_brand_is_hidden_from_translation_and_restored_exactly(self) -> None:
        source = "Win's VPN keeps Win's VPN branding exact."
        protected = protect_literals(source)
        self.assertNotIn("Win's VPN", protected)
        self.assertEqual(protected.count("ZXQ742693851QXZ"), 2)
        self.assertEqual(restore_literals(protected), source)
        self.assertEqual(
            restore_literals("zxqwinsvpnbrandqxz service"),
            "Win's VPN service",
        )

    def test_unrelated_text_is_unchanged(self) -> None:
        source = "Privacy Policy"
        self.assertEqual(protect_literals(source), source)
        self.assertEqual(restore_literals(source), source)

    def test_legacy_or_format_character_placeholders_are_removed(self) -> None:
        payload: dict[str, object] = {
            "ja": {"a": "__\u200bWINSVPN_BRAND__ app"},
            "hi": {"b": "WinSVPNBRAND endpoint"},
            "fr": {"c": "Logo ZXQWINSVPNBMARQUEQXZ"},
            "zh": {"d": "ZXQWINSVPN\u54c1\u724cQXZ\u6807\u5fd7"},
        }
        self.assertEqual(sanitize_translation_placeholders(payload), 4)
        self.assertEqual(payload["ja"]["a"], "Win's VPN app")
        self.assertEqual(payload["hi"]["b"], "Win's VPN endpoint")
        self.assertEqual(payload["fr"]["c"], "Logo Win's VPN")
        self.assertEqual(payload["zh"]["d"], "Win's VPN\u6807\u5fd7")

    def test_strict_json_rejects_duplicate_and_nonfinite_values(self) -> None:
        hostile = (
            '{"es":{"key":"first","key":"second"}}',
            '{"es":{"key":NaN}}',
            '{"es":{"key":Infinity}}',
            '{"es":{"key":-Infinity}}',
            '{"es":{"key":1e9999}}',
        )
        for payload in hostile:
            with self.subTest(payload=payload):
                with self.assertRaises(fill.TranslationTransportError):
                    fill.strict_json_loads(payload)

    def test_translation_file_schema_fails_closed(self) -> None:
        hostile = (
            "[]",
            '{"EN":{"key":"value"}}',
            '{"en":[]}',
            '{"en":{"key":7}}',
            '{"en":{"key":"first","key":"second"}}',
            '{"en":{"key":NaN}}',
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "major.json"
            for payload in hostile:
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf-8")
                    with self.assertRaises(fill.TranslationTransportError):
                        fill.load_translation_map(path)
            path.write_text('{"en":{"Hello":"Hello"},"zh-CN":{}}', encoding="utf-8")
            self.assertEqual(
                fill.load_translation_map(path),
                {"en": {"Hello": "Hello"}, "zh-CN": {}},
            )

    def test_official_request_uses_exact_url_and_api_key_header(self) -> None:
        payload = {"data": {"translations": [{"translatedText": "Hola"}]}}
        with mock.patch.object(fill, "_read_exact_json", return_value=payload) as reader:
            self.assertEqual(
                fill.translate_official("temporary-test-key", "es", ["Hello"]),
                {"Hello": "Hola"},
            )
        request = reader.call_args.args[0]
        self.assertEqual(request.full_url, fill.API_URL)
        self.assertEqual(request.get_method(), "POST")
        self.assertNotIn("temporary-test-key", request.full_url)
        self.assertEqual(request.get_header("X-goog-api-key"), "temporary-test-key")
        self.assertEqual(
            json.loads(request.data.decode("utf-8")),
            {"q": ["Hello"], "source": "en", "target": "es", "format": "text"},
        )
        self.assertEqual(reader.call_args.kwargs["expected_url"], fill.API_URL)

    def test_official_response_cardinality_and_shape_fail_closed(self) -> None:
        hostile = (
            {},
            {"data": {}},
            {"data": {"translations": []}},
            {"data": {"translations": [{"translatedText": 7}]}},
        )
        for payload in hostile:
            with self.subTest(payload=payload):
                with mock.patch.object(fill, "_read_exact_json", return_value=payload):
                    with self.assertRaises(fill.TranslationTransportError):
                        fill.translate_official(
                            "temporary-test-key",
                            "es",
                            ["Hello"],
                        )

    def test_api_key_and_target_are_header_safe(self) -> None:
        hostile_keys = ("", " key", "key ", "key\nvalue", "key\x00value", "x" * 4097)
        for api_key in hostile_keys:
            with self.subTest(api_key=repr(api_key)):
                with self.assertRaises(fill.TranslationTransportError):
                    fill.translate_official(api_key, "es", ["Hello"])
        for target in ("", "ES", "es?key=value", "es\nX-Evil: value", "../es"):
            with self.subTest(target=repr(target)):
                with self.assertRaises(fill.TranslationTransportError):
                    fill.translate_official(
                        "temporary-test-key",
                        target,
                        ["Hello"],
                    )

    def test_public_segments_require_string_source_and_translation(self) -> None:
        hostile = (
            [],
            [[{"unexpected": 1}, "Hello"]],
            [["Hola", {"unexpected": 1}]],
            [["Hola"]],
        )
        for segments in hostile:
            payload = [segments]
            with self.subTest(payload=payload):
                with mock.patch.object(fill, "_read_exact_json", return_value=payload):
                    with self.assertRaises(fill.TranslationTransportError):
                        fill.public_request("es", "Hello")

    def test_public_batch_and_fallback_reject_source_drift(self) -> None:
        with mock.patch.object(
            fill,
            "public_request",
            return_value=[["Adios", "Different source"]],
        ):
            self.assertEqual(fill.translate_public_batch("es", ["Hello"]), {})
            self.assertEqual(
                fill.translate_public("es", ["Hello"], delay=0, retries=0),
                {},
            )

    def test_reviewed_urls_reject_origin_and_component_drift(self) -> None:
        hostile = (
            "http://translation.googleapis.com/language/translate/v2",
            "https://attacker.invalid/language/translate/v2",
            "https://translation.googleapis.com:444/language/translate/v2",
            "https://translation.googleapis.com:notaport/language/translate/v2",
            "https://user@translation.googleapis.com/language/translate/v2",
            "https://translation.googleapis.com/language/translate/v2/extra",
            "https://translation.googleapis.com/language/translate/v2?key=secret",
            "https://translation.googleapis.com/language/translate/v2#fragment",
        )
        for url in hostile:
            with self.subTest(url=url):
                with self.assertRaises(fill.TranslationTransportError):
                    fill._validate_url(
                        url,
                        expected_host="translation.googleapis.com",
                        expected_path="/language/translate/v2",
                        allow_query=False,
                    )

    def test_redirect_is_refused_without_a_second_request(self) -> None:
        handler = fill._NoRedirectHandler()
        with self.assertRaisesRegex(
            fill.TranslationTransportError,
            "redirect refused",
        ):
            handler.redirect_request(
                mock.Mock(),
                mock.Mock(),
                307,
                "Temporary Redirect",
                {},
                "https://attacker.invalid/target",
            )

    def test_opener_explicitly_disables_proxies(self) -> None:
        sentinel = object()
        with mock.patch.object(
            fill.urllib.request,
            "build_opener",
            return_value=sentinel,
        ) as builder:
            self.assertIs(fill._build_opener(), sentinel)
        handlers = builder.call_args.args
        self.assertEqual(len(handlers), 2)
        self.assertIsInstance(handlers[0], fill.urllib.request.ProxyHandler)
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], fill._NoRedirectHandler)

    def test_response_url_content_type_size_and_json_are_bound(self) -> None:
        class FakeResponse:
            status = 200

            def __init__(
                self,
                *,
                url: str = "https://expected.invalid/value",
                content_type: str = "application/json",
                body: bytes = b'{"ok":true}',
                content_length: str | None = None,
            ) -> None:
                self._url = url
                self._body = body
                self.headers: object = {"Content-Type": content_type}
                if content_length is not None:
                    self.headers["Content-Length"] = content_length

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def getcode(self) -> int:
                return self.status

            def geturl(self) -> str:
                return self._url

            def read(self, limit: int) -> bytes:
                return self._body[:limit]

        class FakeOpener:
            def __init__(self, response: FakeResponse) -> None:
                self.response = response

            def open(self, request: object, timeout: int) -> FakeResponse:
                del request, timeout
                return self.response

        class DuplicateHeaders:
            def get_all(self, name: str) -> list[str] | None:
                if name.lower() == "content-type":
                    return ["application/json", "text/html"]
                return None

        request = fill.urllib.request.Request("https://expected.invalid/value")
        hostile = (
            FakeResponse(url="https://other.invalid/value"),
            FakeResponse(content_type="text/html"),
            FakeResponse(content_length="not-an-integer"),
            FakeResponse(content_length="-1"),
            FakeResponse(content_length=str(fill.MAX_RESPONSE_BYTES + 1)),
            FakeResponse(body=b'{"value":NaN}'),
            FakeResponse(body=b'{"value":1e9999}'),
            FakeResponse(body=b'{"value":1,"value":2}'),
        )
        duplicate = FakeResponse()
        duplicate.headers = DuplicateHeaders()
        hostile += (duplicate,)
        for response in hostile:
            with self.subTest(response=response):
                with mock.patch.object(
                    fill,
                    "_build_opener",
                    return_value=FakeOpener(response),
                ):
                    with self.assertRaises(fill.TranslationTransportError):
                        fill._read_exact_json(
                            request,
                            expected_url="https://expected.invalid/value",
                            timeout=5,
                        )


class TranslationIntegrityRefusalTests(unittest.TestCase):
    """Defect shapes taken from the pre-repair web/i18n/major.json."""

    GET_SECTION = (
        "The Get Win's VPN section offers monthly, yearly, and lifetime options. "
        "PayPal subscription renewals and provisioning are intended to sync "
        "automatically with the control hub."
    )

    def assertRefused(self, source: str, value: str) -> None:
        with self.assertRaises(fill.TranslationTransportError):
            fill._translation_ready_value(source, value)

    def test_unknown_placeholder_envelopes_are_refused_not_rewritten(self) -> None:
        cases = (
            (self.GET_SECTION, "Usasishaji wa ZZZPAYPAYPALZZZ unaposanidiwa."),
            ("Win's VPN logo", "Logo ZZZWINVPPNPLAINZZZ"),
            (
                "Win's VPN\u2122 | AI-Powered No-Logs VPN Made in America",
                "\u0417\u0417\u0417\u0412\u0418\u041d\u0412\u041f\u041d"
                "\u0420\u0415\u0413\u0417\u0417\u0417 | VPN",
            ),
            ("Android and Windows first, then macOS/iOS.", "Android Windows macOS/ZZIOSZZZZ"),
            ("Integrate iOS and MacOS apps.", "iOSBRAND MacOS"),
            ("Android VpnService disclosure.", "Android VpnService ANDROIDMARKA"),
        )
        for source, value in cases:
            with self.subTest(value=value):
                self.assertRefused(source, value)
        self.assertNotIn("Win's VPN", restore_literals("ZZZPAYPAYPALZZZ"))
        self.assertNotIn("Win's VPN", restore_literals("ZZWINNPROTOCOLZZZ"))

    def test_stray_z_and_zero_width_contamination_are_refused(self) -> None:
        self.assertRefused(
            "When Android asks, allow Win's VPN.",
            "ZAndroid ZWin's VPN",
        )
        self.assertRefused("Windows demo video", "Video WindowsZ")
        self.assertRefused("caused by misuse", "causados \u200b\u200bpor mal uso")

    def test_changed_protected_names_and_appended_brackets_are_refused(self) -> None:
        self.assertRefused("Coalition Inc.", "Coalici\u00f3n Inc.")
        self.assertRefused("Win Empire LLC logo", "Gagner le logo Empire LLC")
        self.assertRefused("Android safety mode.", "\u5b89\u5353\u5b89\u5168\u6a21\u5f0f\u3002")
        self.assertRefused("Win's VPN logo", "Wins VPN-logo")
        self.assertRefused("Win's VPN logo", "Win's VPN-logo (Win's VPN).")
        self.assertRefused(
            "See the Windows desktop app connect securely.",
            "Voir l'application Windows se connecter avec Winn Protocol\u00ae.",
        )

    def test_exact_names_and_protected_placeholder_are_accepted(self) -> None:
        self.assertEqual(
            fill._translation_ready_value("Win's VPN logo", "Logo ZXQ742693851QXZ"),
            ("Logo Win's VPN", True),
        )
        self.assertEqual(
            fill._translation_ready_value("Coalition Inc.", "Coalition Inc. (assureur)"),
            ("Coalition Inc. (assureur)", False),
        )
        self.assertEqual(
            fill._translation_ready_value(
                "Payments are processed by PayPal.",
                "Maksut k\u00e4sitell\u00e4\u00e4n PayPalilla.",
            ),
            ("Maksut k\u00e4sitell\u00e4\u00e4n PayPalilla.", False),
        )

    def test_defective_aggregate_value_is_retranslated_not_seeded(self) -> None:
        fixture = RepositoryFixture(self)
        fixture.major["fr"]["Hello"] = "ZZZWINVPPNPLAINZZZ Bonjour"
        fixture._write_sources()
        fixture.contract = fixture._write_contract()
        fixture.contract_sha256 = hashlib.sha256(
            fixture.contract_path.read_bytes()
        ).hexdigest()
        observed: list[str] = []

        def record(
            provider: str,
            api_key: str | None,
            target: str,
            strings: list[str],
            delay: float,
        ) -> dict[str, str]:
            del provider, api_key, target, delay
            observed.extend(strings)
            return {source: f"FR: {source}" for source in strings}

        with mock.patch.object(fill, "translate_strings", side_effect=record):
            fixture.invoke("dry-run")
        self.assertEqual(sorted(observed), ["Email", "Hello"])

    def test_defective_provider_value_fails_closed_without_output(self) -> None:
        fixture = RepositoryFixture(self)

        def leaky(
            provider: str,
            api_key: str | None,
            target: str,
            strings: list[str],
            delay: float,
        ) -> dict[str, str]:
            del provider, api_key, target, delay
            return {source: f"ZZZWINPROTOCOLZZZ {source}" for source in strings}

        with mock.patch.object(fill, "translate_strings", side_effect=leaky):
            with self.assertRaises(fill.TranslationTransportError):
                fixture.invoke("create")
        self.assertFalse(fixture.locale_path.exists())

    def test_repository_catalog_values_pass_the_refusal_rules(self) -> None:
        major = json.loads(
            (TOOLS.parent / "web" / "i18n" / "major.json").read_text(encoding="utf-8")
        )
        defective = [
            (locale, key)
            for locale, mapping in major.items()
            if locale != "en"
            for key, value in mapping.items()
            if fill.translation_integrity_defects(key, value)
        ]
        self.assertEqual(defective[:20], [], f"{len(defective)} defective values")


class SplitSourceArchitectureTests(unittest.TestCase):
    def test_create_emits_exact_bound_document_and_never_mutates_major(self) -> None:
        fixture = RepositoryFixture(self)
        major_before = fixture.major_path.read_bytes()
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=complete_provider,
        ) as translator:
            result = fixture.invoke("create")
        self.assertEqual(fixture.major_path.read_bytes(), major_before)
        self.assertTrue(fixture.locale_path.is_file())
        source = contract_tool.strict_json_loads(
            fixture.locale_path.read_bytes(),
            label="created locale source",
        )
        self.assertEqual(tuple(source), contract_tool.LOCALE_DOCUMENT_KEYS)
        self.assertEqual(source["schema"], contract_tool.LOCALE_SOURCE_SCHEMA)
        self.assertEqual(source["locale"], "fr")
        self.assertEqual(
            source["english_source_identity_sha256"],
            fixture.contract["english_source"]["identity_sha256"],
        )
        self.assertEqual(
            source["instant_locale_inventory_sha256"],
            fixture.contract["instant_locale_inventory"]["identity_sha256"],
        )
        self.assertEqual(
            source["translatable_static_keys_sha256"],
            fixture.contract["key_classification"][
                "translatable_static_keys_sha256"
            ],
        )
        keys = fixture.contract["key_classification"]["translatable_static_keys"]
        self.assertEqual(list(source["translations"]), keys)
        self.assertEqual(source["translations"]["Hello"], "Bonjour")
        self.assertEqual(translator.call_args.args[3], ["Email"])
        self.assertEqual(result.seeded_count, 1)
        self.assertEqual(result.translated_count, 1)
        self.assertEqual(
            fixture.locale_path.read_bytes(),
            contract_tool.canonical_json_bytes(source, ensure_ascii=False),
        )

    def test_dry_run_is_ascii_and_does_not_write(self) -> None:
        fixture = RepositoryFixture(self)
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=complete_provider,
        ):
            result = fixture.invoke("dry-run")
        self.assertFalse(fixture.locale_path.exists())
        diagnostic = fill._ascii_text(
            f"locale={result.locale} path={result.output_path} sha256={result.payload_sha256}"
        )
        diagnostic.encode("ascii")

    def test_verify_is_read_only_and_never_calls_transport(self) -> None:
        fixture = RepositoryFixture(self)
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=complete_provider,
        ):
            fixture.invoke("create")
        major_before = fixture.major_path.read_bytes()
        source_before = fixture.locale_path.read_bytes()
        major_stat = fixture.major_path.stat()
        source_stat = fixture.locale_path.stat()
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=AssertionError("verify called transport"),
        ):
            result = fixture.invoke("verify", api_key=None)
        self.assertEqual(result.mode, "verify")
        self.assertEqual(fixture.major_path.read_bytes(), major_before)
        self.assertEqual(fixture.locale_path.read_bytes(), source_before)
        self.assertEqual(fixture.major_path.stat().st_mtime_ns, major_stat.st_mtime_ns)
        self.assertEqual(fixture.locale_path.stat().st_mtime_ns, source_stat.st_mtime_ns)

    def test_existing_output_refuses_overwrite(self) -> None:
        fixture = RepositoryFixture(self)
        fixture.locale_path.write_bytes(b"existing bytes\n")
        major_before = fixture.major_path.read_bytes()
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=AssertionError("existing output reached transport"),
        ):
            with self.assertRaisesRegex(
                fill.TranslationTransportError,
                "refuses to overwrite",
            ):
                fixture.invoke("create")
        self.assertEqual(fixture.locale_path.read_bytes(), b"existing bytes\n")
        self.assertEqual(fixture.major_path.read_bytes(), major_before)

    def test_partial_provider_result_leaves_no_output(self) -> None:
        fixture = RepositoryFixture(self)
        with mock.patch.object(fill, "translate_strings", return_value={}):
            with self.assertRaisesRegex(
                fill.TranslationTransportError,
                "partial or unexpected",
            ):
                fixture.invoke("create")
        self.assertFalse(fixture.locale_path.exists())
        self.assertEqual(
            [path.name for path in fixture.locale_directory.iterdir()],
            [],
        )

    def test_publication_failure_cleans_temporary_output(self) -> None:
        fixture = RepositoryFixture(self)
        with (
            mock.patch.object(
                fill,
                "translate_strings",
                side_effect=complete_provider,
            ),
            mock.patch.object(
                fill,
                "_rename_exclusive",
                side_effect=OSError("mocked publication refusal"),
            ),
        ):
            with self.assertRaisesRegex(
                fill.TranslationTransportError,
                "atomically without replacement",
            ):
                fixture.invoke("create")
        self.assertFalse(fixture.locale_path.exists())
        self.assertEqual(list(fixture.locale_directory.iterdir()), [])

    def test_exact_contract_and_validator_hashes_are_required(self) -> None:
        for field in ("contract", "validator"):
            fixture = RepositoryFixture(self)
            kwargs = {f"{field}_sha256": "0" * 64}
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    fill.TranslationTransportError,
                    "binding mismatch",
                ):
                    fixture.invoke("dry-run", **kwargs)
            self.assertFalse(fixture.locale_path.exists())

    def test_missing_contract_is_refused_before_transport(self) -> None:
        fixture = RepositoryFixture(self)
        fixture.contract_path.unlink()
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=AssertionError("missing contract reached transport"),
        ):
            with self.assertRaisesRegex(
                fill.TranslationTransportError,
                "unsafe or unavailable",
            ):
                fixture.invoke("create")

    def test_cross_locale_and_cross_contract_drift_are_rejected(self) -> None:
        variants = ("locale", "contract")
        for variant in variants:
            fixture = RepositoryFixture(self)
            with mock.patch.object(
                fill,
                "translate_strings",
                side_effect=complete_provider,
            ):
                fixture.invoke("create")
            source = contract_tool.strict_json_loads(
                fixture.locale_path.read_bytes(),
                label="locale source",
            )
            if variant == "locale":
                source["locale"] = "de"
                message = "identity mismatch"
            else:
                source["english_source_identity_sha256"] = "0" * 64
                message = "binding drift"
            fixture.locale_path.write_bytes(
                contract_tool.canonical_json_bytes(source, ensure_ascii=False)
            )
            with self.subTest(variant=variant):
                with self.assertRaisesRegex(
                    fill.TranslationTransportError,
                    message,
                ):
                    fixture.invoke("verify", api_key=None)

    def test_path_substitution_during_provider_call_is_refused(self) -> None:
        fixture = RepositoryFixture(self)
        parked = fixture.locale_directory.with_name("locales-parked")

        def substitute(*args: object, **kwargs: object) -> dict[str, str]:
            del kwargs
            fixture.locale_directory.rename(parked)
            fixture.locale_directory.mkdir()
            strings = args[3]
            return {source: f"FR: {source}" for source in strings}

        with mock.patch.object(fill, "translate_strings", side_effect=substitute):
            with self.assertRaisesRegex(
                fill.TranslationTransportError,
                "directory changed",
            ):
                fixture.invoke("create")
        self.assertFalse(fixture.locale_path.exists())
        self.assertFalse((parked / "fr.json").exists())

    def test_changed_major_during_provider_call_is_refused(self) -> None:
        fixture = RepositoryFixture(self)

        def mutate_major(*args: object, **kwargs: object) -> dict[str, str]:
            del kwargs
            fixture.major["fr"]["Hello"] = "Bonjour modifie"
            fixture.major_path.write_bytes(fixture._canonical(fixture.major))
            strings = args[3]
            return {source: f"FR: {source}" for source in strings}

        with mock.patch.object(fill, "translate_strings", side_effect=mutate_major):
            with self.assertRaisesRegex(
                fill.TranslationTransportError,
                "file changed",
            ):
                fixture.invoke("create")
        self.assertFalse(fixture.locale_path.exists())

    def test_duplicate_and_nonfinite_major_inputs_fail_closed(self) -> None:
        hostile = (
            b'{"en":{},"fr":{"Hello":"un","Hello":"deux"},"de":{}}',
            b'{"en":{},"fr":{"Hello":NaN},"de":{}}',
            b'{"en":{},"fr":{"Hello":Infinity},"de":{}}',
            b'{"en":{},"fr":{"Hello":1e9999},"de":{}}',
        )
        for payload in hostile:
            fixture = RepositoryFixture(self)
            fixture.major_path.write_bytes(payload)
            with self.subTest(payload=payload):
                with self.assertRaises(fill.TranslationTransportError):
                    fixture.invoke("dry-run")

    def test_symlink_hardlink_fifo_and_writable_parent_are_refused(self) -> None:
        kinds = ("symlink", "hardlink", "fifo", "writable-parent")
        for kind in kinds:
            fixture = RepositoryFixture(self)
            if kind == "writable-parent":
                fixture.locale_directory.chmod(0o777)
            else:
                original = fixture.major_path.read_bytes()
                fixture.major_path.unlink()
                outside = fixture.root / f"outside-{kind}"
                if kind == "symlink":
                    outside.write_bytes(original)
                    fixture.major_path.symlink_to(outside)
                elif kind == "hardlink":
                    outside.write_bytes(original)
                    os.link(outside, fixture.major_path)
                elif kind == "fifo":
                    os.mkfifo(fixture.major_path)
            with self.subTest(kind=kind):
                with self.assertRaises(fill.TranslationTransportError):
                    fixture.invoke("dry-run")

    def test_symlinked_output_parent_and_existing_output_symlink_are_refused(self) -> None:
        for kind in ("parent", "output"):
            fixture = RepositoryFixture(self)
            outside = fixture.root / f"outside-{kind}"
            outside.mkdir()
            if kind == "parent":
                fixture.locale_directory.rmdir()
                fixture.locale_directory.symlink_to(outside, target_is_directory=True)
            else:
                target = outside / "fr.json"
                target.write_bytes(b"outside\n")
                fixture.locale_path.symlink_to(target)
            with self.subTest(kind=kind):
                with self.assertRaises(fill.TranslationTransportError):
                    fixture.invoke("create")
            if kind == "output":
                self.assertEqual(target.read_bytes(), b"outside\n")

    def test_hardlinked_existing_locale_source_is_refused_in_verify(self) -> None:
        fixture = RepositoryFixture(self)
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=complete_provider,
        ):
            fixture.invoke("create")
        second = fixture.root / "second-link.json"
        os.link(fixture.locale_path, second)
        with self.assertRaisesRegex(
            fill.TranslationTransportError,
            "identity is unsafe",
        ):
            fixture.invoke("verify", api_key=None)

    def test_locale_selection_refresh_and_legacy_path_options_fail_closed(self) -> None:
        fixture = RepositoryFixture(self)
        hostile_locales = ([], ["en"], ["es"], ["fr", "fr"], ["fr", "de"])
        for locales in hostile_locales:
            with self.subTest(locales=locales):
                with self.assertRaises(fill.TranslationTransportError):
                    fixture.invoke("dry-run", locales=locales)
        with self.assertRaisesRegex(
            fill.TranslationTransportError,
            "outside the accepted contract",
        ):
            fixture.invoke("dry-run", refresh_keys=["Not a contract key"])
        for arguments in (
            ["create", "--locale", "fr", "--write"],
            ["create", "--locale", "fr", "--output", "elsewhere.json"],
            ["verify", "--locale", "fr", "--repo=/tmp/other"],
            ["dry-run", "--locale", "fr", "--i18n=web/i18n/major.json"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(fill.TranslationTransportError):
                    fill._refuse_legacy_or_path_options(arguments)

    def test_refresh_only_retranslates_the_selected_contract_key(self) -> None:
        fixture = RepositoryFixture(self)
        observed: list[str] = []

        def record(
            provider: str,
            api_key: str | None,
            target: str,
            strings: list[str],
            delay: float,
        ) -> dict[str, str]:
            del provider, api_key, target, delay
            observed.extend(strings)
            return {source: f"FR: {source}" for source in strings}

        with mock.patch.object(fill, "translate_strings", side_effect=record):
            fixture.invoke("dry-run", refresh_keys=["Hello"])
        self.assertEqual(observed, ["Email", "Hello"])

    def test_canonical_bytes_are_deterministic_across_temp_repositories(self) -> None:
        outputs: list[bytes] = []
        hashes: list[str] = []
        for _ in range(2):
            fixture = RepositoryFixture(self)
            with mock.patch.object(
                fill,
                "translate_strings",
                side_effect=complete_provider,
            ):
                result = fixture.invoke("create")
            outputs.append(fixture.locale_path.read_bytes())
            hashes.append(result.payload_sha256)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(hashes[0], hashes[1])
        self.assertNotIn(b"\r", outputs[0])
        self.assertTrue(outputs[0].endswith(b"\n"))

    def test_created_file_is_regular_single_link_with_expected_mode(self) -> None:
        fixture = RepositoryFixture(self)
        with mock.patch.object(
            fill,
            "translate_strings",
            side_effect=complete_provider,
        ):
            fixture.invoke("create")
        metadata = fixture.locale_path.stat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
