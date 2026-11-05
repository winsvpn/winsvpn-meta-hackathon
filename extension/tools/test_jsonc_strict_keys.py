#!/usr/bin/env python3
"""Direct hostile tests for the extension JSONC parser boundary."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


TOOLS = Path(__file__).resolve().parent
JSONC_PATH = TOOLS / "jsonc.py"


def _load_current_jsonc():
    spec = importlib.util.spec_from_file_location("winsvpn_strict_jsonc", JSONC_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


jsonc = _load_current_jsonc()

SECURITY_KEYS = (
    "allowed_origins",
    "allowed_extensions",
    "permissions",
    "nativeMessaging",
    "browser_specific_settings",
    "id",
)
NON_FINITE_CONSTANTS = ("NaN", "Infinity", "-Infinity")


def test_imports_the_exact_current_jsonc_source() -> None:
    assert Path(jsonc.__file__).resolve() == JSONC_PATH.resolve()


@pytest.mark.parametrize("key", SECURITY_KEYS)
@pytest.mark.parametrize("placement", ("top-level", "nested"))
def test_duplicate_security_keys_fail_closed(key: str, placement: str) -> None:
    if placement == "top-level":
        payload = f'{{"{key}": 1, "{key}": 2}}'
    else:
        payload = f'{{"policy": {{"{key}": 1, "{key}": 2}}}}'

    with pytest.raises(json.JSONDecodeError, match=f"duplicate JSON key: {key}"):
        jsonc.loads(payload)


@pytest.mark.parametrize(
    ("payload", "key"),
    (
        (
            '{"allowed_origins": ["chrome-extension://one/"], '
            '// the second key must not replace the first\n'
            '"allowed_origins": ["chrome-extension://two/"]}',
            "allowed_origins",
        ),
        (
            '{"browser_specific_settings": {"gecko": {"id": "one"}}, '
            '/* comments cannot hide an identity replacement */ '
            '"browser_specific_settings": {"gecko": {"id": "two"}}}',
            "browser_specific_settings",
        ),
        (
            '{"policy": {"allowed_extensions": ["one"], '
            '// nested duplicate\n'
            '"allowed_extensions": ["two"]}}',
            "allowed_extensions",
        ),
        (
            '{"policy": {"id": "one", '
            '/* nested duplicate */ "id": "two"}}',
            "id",
        ),
    ),
)
def test_comments_cannot_hide_duplicate_keys(payload: str, key: str) -> None:
    with pytest.raises(json.JSONDecodeError, match=f"duplicate JSON key: {key}"):
        jsonc.loads(payload)


@pytest.mark.parametrize(
    ("payload", "key"),
    (
        (
            '{"permissions": ["storage"], '
            '"permissions": ["nativeMessaging"],}',
            "permissions",
        ),
        (
            '{"browser_specific_settings": {"gecko": {'
            '"id": "one", "id": "two",},},}',
            "id",
        ),
    ),
)
def test_trailing_comma_cleanup_does_not_erase_duplicate_evidence(
    payload: str, key: str
) -> None:
    with pytest.raises(json.JSONDecodeError, match=f"duplicate JSON key: {key}"):
        jsonc.loads(payload)


@pytest.mark.parametrize("constant", NON_FINITE_CONSTANTS)
def test_nested_non_finite_constants_fail_closed(constant: str) -> None:
    payload = '{"policy": {"routes": [{"weight": ' + constant + '}]}}'

    with pytest.raises(ValueError, match=f"invalid JSON number: {constant}"):
        jsonc.loads(payload)


@pytest.mark.parametrize(
    ("payload", "exception", "message"),
    (
        (
            '{"id": "one", "id": "two",}',
            json.JSONDecodeError,
            "duplicate JSON key: id",
        ),
        ('{"nested": {"value": NaN},}', ValueError, "invalid JSON number: NaN"),
        (
            '{"nested": {"value": Infinity},}',
            ValueError,
            "invalid JSON number: Infinity",
        ),
        (
            '{"nested": {"value": -Infinity},}',
            ValueError,
            "invalid JSON number: -Infinity",
        ),
        (
            '{"id": "ok"} /* unterminated',
            json.JSONDecodeError,
            "Extra data",
        ),
    ),
)
def test_direct_trailing_comma_helper_cannot_bypass_strict_decoding(
    payload: str, exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        jsonc._drop_trailing_commas(payload)


def test_honest_comments_urls_escapes_and_trailing_commas_parse() -> None:
    payload = r'''
    {
      // A URL and comment markers inside strings are data, not comments.
      "homepage_url": "https://winsvpn.org/path//route?note=/*literal*/",
      "description": "escaped quote: \"safe\" and // still text",
      "permissions": [
        "nativeMessaging",
        "storage", // honest trailing item comment
      ],
      /* An honest block comment between members. */
      "browser_specific_settings": {
        "gecko": {
          "id": "companion@winsvpn.org",
        },
      },
    }
    '''

    parsed = jsonc.loads(payload)

    assert parsed["homepage_url"] == (
        "https://winsvpn.org/path//route?note=/*literal*/"
    )
    assert parsed["description"] == 'escaped quote: "safe" and // still text'
    assert parsed["permissions"] == ["nativeMessaging", "storage"]
    assert (
        parsed["browser_specific_settings"]["gecko"]["id"]
        == "companion@winsvpn.org"
    )


def test_honest_line_comment_may_end_at_eof() -> None:
    assert jsonc.loads('{"id": "ok"} // comment ends at EOF') == {"id": "ok"}


def test_complete_block_comment_after_document_is_allowed() -> None:
    assert jsonc.loads('{"id": "ok"} /* complete */') == {"id": "ok"}


@pytest.mark.parametrize(
    "payload",
    (
        '{"id": "ok"} /*',
        '{"id": "ok"} /* unterminated',
        '{"id": "ok"} /*\nunterminated',
        '/* comment starts before the document',
    ),
)
def test_unterminated_block_comments_fail_at_the_comment_start(payload: str) -> None:
    expected_position = payload.index("/*")

    with pytest.raises(json.JSONDecodeError, match="unterminated block comment") as exc:
        jsonc.loads(payload)

    assert exc.value.pos == expected_position


@pytest.mark.parametrize(
    "payload",
    (
        '{"permissions": [}',
        '{"permissions": []',
        '{"id": "unterminated}',
        '{"id": "ok"} trailing bytes',
        '[1,,2]',
        '{"id": "ok" // line comment cannot supply the missing brace',
    ),
)
def test_malformed_or_unterminated_json_fails_closed(payload: str) -> None:
    with pytest.raises(json.JSONDecodeError):
        jsonc.loads(payload)


def test_load_file_uses_the_same_strict_jsonc_contract(tmp_path: Path) -> None:
    path = tmp_path / "manifest.jsonc"
    path.write_text(
        '{\n'
        '  // reviewed identity\n'
        '  "allowed_extensions": ["companion@winsvpn.org"],\n'
        '}\n',
        encoding="utf-8",
    )

    assert jsonc.load_file(path) == {
        "allowed_extensions": ["companion@winsvpn.org"]
    }


@pytest.mark.parametrize(
    "payload",
    (
        '{"allowed_origins": ["one"], "allowed_origins": ["two"]}',
        '{"nested": {"value": NaN}}',
        '{"id": "ok"} /* unterminated',
    ),
)
def test_load_file_rejects_hostile_content(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "hostile.jsonc"
    path.write_text(payload, encoding="utf-8")

    with pytest.raises((json.JSONDecodeError, ValueError)):
        jsonc.load_file(path)
