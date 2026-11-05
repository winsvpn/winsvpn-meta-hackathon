"""Strip // and /* */ comments from JSON without breaking string contents.

A manifest cannot carry comments -- Chrome reports unrecognised keys as
warnings, so the reasoning for a permission cannot live in the file as data. The
source manifests are therefore JSONC and the build emits plain JSON, which means
the reviewed artefact carries the justification and the shipped artefact stays
valid.

The scanner below is a character-level state machine rather than a regular
expression, because a regular expression will eventually meet a string
containing "//" -- a URL, a comment about a comment -- and silently truncate the
file at it.
"""

from __future__ import annotations

import json


class _DuplicateKeyError(json.JSONDecodeError):
    """A JSON object repeated a key before it could become a dict."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}", "", 0)
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"invalid JSON number: {value}")


def _loads_json(text: str):
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def strip_comments(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    escape = False

    while i < n:
        ch = text[i]

        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                comment_start = i
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    if text[i] == "\n":
                        out.append("\n")  # keep line numbers usable in errors
                    i += 1
                if i + 1 >= n:
                    raise json.JSONDecodeError(
                        "unterminated block comment", text, comment_start
                    )
                i += 2
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def loads(text: str):
    """Parse JSONC, tolerating a trailing comma left behind by a removed entry."""
    stripped = strip_comments(text)
    try:
        return _loads_json(stripped)
    except _DuplicateKeyError:
        raise
    except json.JSONDecodeError:
        cleaned = _drop_trailing_commas(stripped)
        return _loads_json(cleaned)


def _drop_trailing_commas(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            continue
        if ch == ",":
            rest = text[i + 1 :].lstrip()
            if rest[:1] in ("}", "]"):
                continue
        out.append(ch)
    cleaned = "".join(out)
    # Some preflight consumers need the normalized JSON text so they can apply
    # additional strict decoder options. Validate here as well so they cannot
    # bypass the duplicate-key invariant by calling this helper directly.
    _loads_json(cleaned)
    return cleaned


def load_file(path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())
