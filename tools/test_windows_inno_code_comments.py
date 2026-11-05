#!/usr/bin/env python3
"""The Inno Setup [Code] section must lex as Pascal Script.

A Pascal brace comment ends at the FIRST closing brace, so a comment that names
an Inno constant such as {tmp} or {app} closes early and the rest of the
comment is compiled as code. That shipped once (R20 A1 audit follow-up) and was
only caught by ISCC on the Windows build guest ("'BEGIN' expected"). This test
lexes the [Code] section the way the Pascal Script compiler does and refuses a
brace comment that contains an opening brace, and a parenthesis-star comment
that contains its own opener.

Run: python3 -B tools/test_windows_inno_code_comments.py
"""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = (ROOT / "installer/windows/winsvpn.iss",)


def comment_faults(text: str) -> list[str]:
    """Return one message per comment the Pascal Script lexer would end early."""
    marker = text.find("[Code]")
    if marker < 0:
        return []
    code = text[marker + len("[Code]"):]
    line = text[:marker].count("\n") + 1
    faults: list[str] = []
    i = 0
    n = len(code)
    while i < n:
        c = code[i]
        if c == "\n":
            line += 1
            i += 1
        elif c == "'":
            end = code.find("'", i + 1)
            if end < 0:
                faults.append(f"line {line}: unterminated string")
                break
            line += code.count("\n", i, end)
            i = end + 1
        elif code.startswith("//", i):
            end = code.find("\n", i)
            i = n if end < 0 else end
        elif code.startswith("(*", i):
            end = code.find("*)", i + 2)
            if end < 0:
                faults.append(f"line {line}: unterminated (* comment")
                break
            if "(*" in code[i + 2:end]:
                faults.append(f"line {line}: (* comment contains another (*")
            line += code.count("\n", i, end)
            i = end + 2
        elif c == "{":
            end = code.find("}", i + 1)
            if end < 0:
                faults.append(f"line {line}: unterminated brace comment")
                break
            if "{" in code[i + 1:end]:
                faults.append(
                    f"line {line}: brace comment contains '{{' and ends at the first '}}'"
                )
            line += code.count("\n", i, end)
            i = end + 1
        else:
            i += 1
    return faults


class InnoCodeCommentTests(unittest.TestCase):
    def test_every_code_section_comment_lexes_whole(self) -> None:
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                self.assertEqual(comment_faults(script.read_text(encoding="utf-8")), [])

    def test_a_brace_comment_naming_an_inno_constant_is_refused(self) -> None:
        bad = "[Code]\n{ Never {tmp}: the user can rewrite it. }\nfunction F: Boolean;\n"
        self.assertEqual(len(comment_faults(bad)), 1)
        self.assertIn("line 2", comment_faults(bad)[0])

    def test_parenthesis_star_comments_may_name_constants(self) -> None:
        good = "[Code]\n(* Never {tmp}: {app} instead. *)\nfunction F: Boolean;\n"
        self.assertEqual(comment_faults(good), [])
        nested = "[Code]\n(* a (* b *) c *)\n"
        self.assertEqual(len(comment_faults(nested)), 1)

    def test_strings_and_line_comments_are_not_comments(self) -> None:
        good = "[Code]\n// {tmp} here is fine\nS := ExpandConstant('{tmp}\\x');\n"
        self.assertEqual(comment_faults(good), [])


if __name__ == "__main__":
    unittest.main()
