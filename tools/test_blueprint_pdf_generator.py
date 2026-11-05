"""Regression test for the blueprint-PDF-generator f-string defect.

Final Recommendations.md ("Non-security tooling defect -- blueprint generator
does not parse") flagged that tools/generate_blueprint_pdf.py:105-112 put a
backslash-containing string literal (`.replace("\\", "/")`) directly inside
an f-string expression part. That grammar restriction was only lifted in
Python 3.12 (PEP 701); this project's tooling is documented to run under the
macOS-default Python 3.9 toolchain (see
docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md), so the old code was a hard
SyntaxError there even though it happily parses on newer interpreters.

Because the whole point of the bug is that it is invisible on a modern
Python, this test cannot simply `ast.parse` the file on whatever interpreter
runs the suite -- that would pass both before and after the fix on Python
3.12+. Instead it statically greps the source for the exact defect shape
(a backslash inside an f-string `{...}` expression) so the check is accurate
regardless of which Python version happens to run the test.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tools" / "generate_blueprint_pdf.py"

# Matches an f-string brace expression that contains a literal backslash,
# e.g. f"{str(path).replace('\\', '/')}" -- exactly the pre-3.12 SyntaxError
# shape. This intentionally does not attempt full Python-string-literal
# parsing (nested braces, escaped quotes, etc.); it only needs to catch the
# concrete pattern the recommendation identified without false-negating on
# variations of it.
_BACKSLASH_IN_FSTRING_EXPR = re.compile(r"f[\"'][^\"'\n]*\{[^{}]*\\\\[^{}]*\}")


class BlueprintGeneratorFStringTests(unittest.TestCase):
    def test_source_has_no_backslash_inside_an_fstring_expression(self):
        source = TARGET.read_text(encoding="utf-8")
        offenders = _BACKSLASH_IN_FSTRING_EXPR.findall(source)
        self.assertEqual(
            offenders,
            [],
            "found an f-string expression containing a backslash -- this is "
            "a SyntaxError on Python < 3.12 (the macOS-default 3.9 included); "
            "move the backslash-containing expression to a plain assignment "
            "before the f-string instead of inlining it in the {...} part.",
        )

    def test_artifact_row_normalizes_and_reports_missing_paths(self):
        # Exercise the real fixed function (not a re-implementation) so this
        # test also catches behavioral regressions, not just the syntax bug.
        namespace: dict = {}
        source = TARGET.read_text(encoding="utf-8")
        match = re.search(r"\ndef artifact_row\(.*?\n\n\n", source, re.DOTALL)
        self.assertIsNotNone(match, "artifact_row() definition not found")
        helper_source = (
            "from pathlib import Path\n"
            "from hashlib import sha256\n"
            "def file_sha256(path):\n"
            "    digest = sha256()\n"
            "    with path.open('rb') as handle:\n"
            "        for chunk in iter(lambda: handle.read(1024 * 1024), b''):\n"
            "            digest.update(chunk)\n"
            "    return digest.hexdigest().upper()\n"
            "def file_size_mb(path):\n"
            "    return f'{path.stat().st_size / (1024 * 1024):.2f} MB'\n"
        )
        exec(compile(helper_source, "helpers", "exec"), namespace)  # noqa: S102
        exec(compile(match.group(0), "artifact_row", "exec"), namespace)  # noqa: S102
        artifact_row = namespace["artifact_row"]

        missing = Path("C:\\fake\\windows\\path\\missing.bin")
        row = artifact_row("Missing", missing)
        self.assertEqual(row, ["Missing", "C:/fake/windows/path/missing.bin", "MISSING"])

        real_row = artifact_row("Self", TARGET)
        self.assertEqual(real_row[0], "Self")
        self.assertIn("generate_blueprint_pdf.py", real_row[1])
        self.assertIn("MB)", real_row[1])
        self.assertRegex(real_row[2], r"^[0-9A-F]{64}$")


if __name__ == "__main__":
    unittest.main()
