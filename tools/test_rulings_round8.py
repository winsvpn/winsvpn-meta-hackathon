#!/usr/bin/env python3
"""Exercise the production rulings parser, including fail-closed errors."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tools/verify_rulings.sh").read_text()
FUNCTIONS = SOURCE[SOURCE.index("stripped() {"):SOURCE.index("\nchecked=0")]


class RulingParserTests(unittest.TestCase):
    def invoke(self, source, suffix=".swift", literal=None):
        with tempfile.TemporaryDirectory(prefix="winsvpn-ruling-test-") as directory:
            path = Path(directory) / ("source" + suffix)
            path.write_text(source)
            command = 'stripped "$1"' if literal is None else 'contains_live "$1" "$2"'
            return subprocess.run(["bash", "-c", FUNCTIONS + "\n" + command,
                                   "test-rulings", str(path), literal or ""],
                                  capture_output=True, text=True, timeout=10)

    def test_multiline_nested_and_line_comments_cannot_satisfy_live_rule(self):
        source = "/*\nstatic let enforceRoutes = true\n/* nested */\n*/\nstatic let enforceRoutes = !true\n"
        result = self.invoke(source, literal="static let enforceRoutes = true")
        self.assertEqual(result.returncode, 1)
        for comment in ("//", "#"):
            self.assertEqual(self.invoke(comment + " static let enforceRoutes = true\n",
                                         literal="static let enforceRoutes = true").returncode, 1)
        self.assertEqual(self.invoke("static let enforceRoutes = true // live\n",
                                    literal="static let enforceRoutes = true").returncode, 0)

    def test_markdown_headings_and_quoted_urls_are_preserved(self):
        heading = "# Approved route posture\n"
        self.assertEqual(self.invoke(heading, ".md").stdout, heading)
        source = 'let url = "https://example.test/a#fragment"\nlet text = "/* literal */"\n'
        self.assertEqual(self.invoke(source).stdout, source)

    def test_unterminated_comment_fails_both_require_and_forbid_search(self):
        for literal in ("enforceRoutes = true", "enforceRoutes = false"):
            result = self.invoke("/*\nenforceRoutes = true\n", literal=literal)
            self.assertEqual(result.returncode, 2)
            self.assertIn("cannot parse", result.stderr)

    # Design v17 2.8 (slice S3): the replay-journal literal is required in the
    # data-plane installer too, and a shell glob there read as a block comment.
    def test_shell_glob_and_path_are_not_comments(self):
        literal = "WINN3_GATEWAY_REPLAY_JOURNAL=1"
        source = 'if [[ "${1:-}" == /* ]]; then\n  cd //srv\nfi\n  ' + literal + "\n"
        self.assertEqual(self.invoke(source, ".sh").stdout, source)
        self.assertEqual(self.invoke(source, ".sh", literal=literal).returncode, 0)
        # The same text outside a shell script keeps the C rules.
        self.assertEqual(self.invoke(source, ".swift", literal=literal).returncode, 2)

    def test_shell_comment_still_cannot_satisfy_live_rule(self):
        literal = "WINN3_GATEWAY_REPLAY_JOURNAL=1"
        for source in ("# " + literal + "\n", "x=0 # " + literal + "\n",
                       '[[ "$1" == /* ]] # ' + literal + "\n"):
            self.assertEqual(self.invoke(source, ".sh", literal=literal).returncode, 1, source)

    def test_installers_parse_and_the_replay_journal_literal_is_live(self):
        # Slice S6: the literal is required in the data-plane installer only.
        # The standalone installer is a tombstone that carries no gateway code.
        literal = "WINN3_GATEWAY_REPLAY_JOURNAL=1"
        text = (ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh").read_text()
        self.assertEqual(self.invoke(text, ".sh").returncode, 0)
        self.assertEqual(self.invoke(text, ".sh", literal=literal).returncode, 0)
        # Commenting the live assignment out must fail the rule.
        commented = text.replace("  " + literal + "\n", "  # " + literal + "\n")
        self.assertNotEqual(commented, text)
        self.assertEqual(self.invoke(commented, ".sh", literal=literal).returncode, 1)
        tombstone = (ROOT / "server" / "wins_winn3_gateway_install.sh").read_text()
        self.assertEqual(self.invoke(tombstone, ".sh").returncode, 0)
        self.assertEqual(self.invoke(tombstone, ".sh", literal=literal).returncode, 1)


if __name__ == "__main__":
    unittest.main()
