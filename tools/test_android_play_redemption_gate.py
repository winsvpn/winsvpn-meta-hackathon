#!/usr/bin/env python3
"""Tests for tools/android_play_redemption_gate.py (release gate S14A)."""
from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "android_play_redemption_gate", TOOLS / "android_play_redemption_gate.py"
)
GATE = importlib.util.module_from_spec(SPEC)
sys.modules["android_play_redemption_gate"] = GATE
SPEC.loader.exec_module(GATE)

MAIN = """\
class S {
  String _t(String english) {
    const localized = <String, Map<String, String>>{
      'my': {
        'Hello': 'Mingalaba',
        // 'Close' is shared with other screens and stays in every build.
        'Close':
            'Pate',
        if (!_googlePlayBuild) ...<String, String>{
          'Redeem a Prepaid Card':
              'ကလေး',
          'Promo bonus days added: {days}':
              'Promo {days}',
          'Interpolated only $days':
              'Burmese only $days',
        },
      },
    };
    return localized['my']?[english] ?? english;
  }

  void _showPaymentOptions(BuildContext context) {
    if (_googlePlayBuild) {
      return;
    }
    final title = _t('Redeem a Prepaid Card');
  }

  Future<void> _showPrepaidRedemption() async {
    if (!_canRedeemPrepaidInApp) return;
  }

  List<Widget> _prepaidRedemptionEntries({required double tvOrder}) {
    if (_googlePlayBuild) return const <Widget>[];
    return <Widget>[Text(_t('Redeem a Prepaid Card'))];
  }

  void account(Map data) {
    data['referral_code'] = 'x';
    final label = _t('Close');
  }
}
"""

R2 = """\
const a = 'Redeem a prepaid card';
const b = 'referral_code';
const c = 'Content-Type';
const d = 'gift';
Widget build() => Text(_tr('Close')) + Text(_tr('Plain acknowledgement text'));
"""

# A comment in an unrelated library must never suppress a needle.
UNRELATED = """\
// TODO: never ship 'Redeem a Prepaid Card' in a Play build.
class U {}
"""


def make_repo(root: Path, main: str = MAIN, r2: str = R2,
              unrelated: str | None = UNRELATED) -> Path:
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "main.dart").write_text(main, encoding="utf-8")
    (root / "lib" / "prepaid_redemption.dart").write_text(r2, encoding="utf-8")
    if unrelated is not None:
        (root / "lib" / "unrelated.dart").write_text(unrelated, encoding="utf-8")
    return root


def make_aab(path: Path, payload: bytes, member: str = "base/lib/arm64-v8a/libapp.so",
             extra: tuple[tuple[str, bytes], ...] = ()) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"manifest")
        if member:
            archive.writestr(member, payload)
        for name, blob in extra:
            archive.writestr(name, blob)
    return path


def understate_member_size(path: Path, name: str, size: int) -> None:
    """Rewrite one central-directory entry's uncompressed size (no zip64)."""
    data = bytearray(path.read_bytes())
    pos = 0
    while (pos := data.find(b"PK\x01\x02", pos)) >= 0:
        name_len = int.from_bytes(data[pos + 28:pos + 30], "little")
        if data[pos + 46:pos + 46 + name_len] == name.encode("ascii"):
            data[pos + 24:pos + 28] = size.to_bytes(4, "little")
            path.write_bytes(bytes(data))
            return
        pos += 4
    raise AssertionError(f"no central-directory entry for {name}")


def _has_lzma() -> bool:
    try:
        import lzma  # noqa: F401
    except ImportError:
        return False
    return True


class DeriveNeedlesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_block_keys_values_and_r2_literals_are_needles(self) -> None:
        needles, excluded = GATE.derive_needles(make_repo(self.root / "r"))
        self.assertIn("Redeem a Prepaid Card", needles)
        self.assertIn("ကလေး", needles)
        self.assertIn("Promo bonus days added: {days}", needles)
        self.assertIn("Redeem a prepaid card", needles)
        self.assertNotIn("Content-Type", needles)
        self.assertNotIn("gift", needles)  # shorter than six characters
        self.assertNotIn("Hello", needles)

    def test_interpolated_literals_are_not_needles(self) -> None:
        needles, _ = GATE.derive_needles(make_repo(self.root / "r"))
        # Dart compiles an interpolation to a concatenation, so the source text
        # can never appear verbatim in a snapshot; counting it inflates the
        # reported needle total without adding coverage.
        self.assertNotIn("Interpolated only $days", needles)
        self.assertNotIn("Burmese only $days", needles)
        self.assertFalse([n for n in needles if "$" in n], needles)

    def test_tr_literals_are_needles_without_a_redemption_keyword(self) -> None:
        needles, _ = GATE.derive_needles(make_repo(self.root / "r"))
        self.assertIn("Plain acknowledgement text", needles)

    def test_pinned_shared_labels_are_excluded(self) -> None:
        needles, excluded = GATE.derive_needles(make_repo(self.root / "r"))
        self.assertEqual(excluded, ["Close", "referral_code"])
        self.assertNotIn("referral_code", needles)
        self.assertNotIn("Close", needles)
        # Uses inside the compiled-out payment sheet do not exclude a needle.
        self.assertIn("Redeem a Prepaid Card", needles)

    def test_a_comment_in_another_library_does_not_exclude_a_needle(self) -> None:
        needles, excluded = GATE.derive_needles(make_repo(self.root / "r"))
        self.assertIn("Redeem a Prepaid Card", needles)
        self.assertNotIn("Redeem a Prepaid Card", excluded)

    def test_an_unpinned_overlap_fails_closed(self) -> None:
        main = MAIN.replace(
            "    final label = _t('Close');",
            "    final label = _t('Close') + _t('Redeem a Prepaid Card');",
        )
        with self.assertRaisesRegex(GATE.GateError, "ALLOWED_EXCLUDED"):
            GATE.derive_needles(make_repo(self.root / "r", main=main))

    def test_missing_block_fails_closed(self) -> None:
        main = MAIN.replace("        if (!_googlePlayBuild) ...<String, String>{\n", "")
        with self.assertRaisesRegex(GATE.GateError, "Play-excluded translation block"):
            GATE.derive_needles(make_repo(self.root / "r", main=main))

    def test_missing_method_fails_closed(self) -> None:
        main = MAIN.replace("  Future<void> _showPrepaidRedemption() async {", "  void other() {")
        with self.assertRaisesRegex(GATE.GateError, "_showPrepaidRedemption"):
            GATE.derive_needles(make_repo(self.root / "r", main=main))

    def test_the_redemption_entry_is_an_r2_source(self) -> None:
        # Owner ruling 2026-10-24: the entry's label is the same R2 literal as
        # the sheet's, and it must stay a needle rather than an overlap.
        needles, excluded = GATE.derive_needles(make_repo(self.root / "r"))
        self.assertIn("Redeem a Prepaid Card", needles)
        self.assertNotIn("Redeem a Prepaid Card", excluded)

    def test_a_missing_redemption_entry_fails_closed(self) -> None:
        main = MAIN.replace(
            "  List<Widget> _prepaidRedemptionEntries({required double tvOrder}) {",
            "  List<Widget> other() {",
        )
        with self.assertRaisesRegex(GATE.GateError, "_prepaidRedemptionEntries"):
            GATE.derive_needles(make_repo(self.root / "r", main=main))

    def test_a_nested_spread_does_not_truncate_the_block(self) -> None:
        # The close is found by brace depth: a nested spread whose own closer
        # sits at the block's indentation must not end the block early and
        # silently drop every needle after it.
        main = MAIN.replace(
            "        if (!_googlePlayBuild) ...<String, String>{\n",
            "        if (!_googlePlayBuild) ...<String, String>{\n"
            "          if (kIsWeb) ...<String, String>{\n"
            "            'WebOnly': 'WebOnlyValue',\n"
            "        },\n",
        )
        needles, _ = GATE.derive_needles(make_repo(self.root / "r", main=main))
        self.assertIn("WebOnly", needles)
        self.assertIn("Redeem a Prepaid Card", needles)
        self.assertIn("ကလေး", needles)
        self.assertIn("Promo bonus days added: {days}", needles)

    def test_a_drifted_block_closer_fails_closed(self) -> None:
        main = MAIN.replace("\n        },\n      },\n", "\n        }\n      },\n")
        self.assertNotEqual(main, MAIN)
        with self.assertRaisesRegex(GATE.GateError, "does not close with"):
            GATE.derive_needles(make_repo(self.root / "r", main=main))

    def test_hex_and_unicode_escapes_become_the_compiled_text(self) -> None:
        # A needle spelled like the escape ('x50', 'u0043') can never match the
        # snapshot, which holds the decoded characters.
        r2 = R2 + (
            "const e = 'Redeem \\x50repaid card';\n"
            "const f = 'Promo \\u0043ode entry';\n"
            "const g = 'Gift card \\u{1F381} redeemed';\n"
            "Widget tr() => Text(_tr('Don\\'t lose this \\u0063ode'));\n"
        )
        needles, _ = GATE.derive_needles(make_repo(self.root / "r", r2=r2))
        self.assertIn("Redeem Prepaid card", needles)
        self.assertIn("Promo Code entry", needles)
        self.assertIn("Gift card \U0001F381 redeemed", needles)
        self.assertIn("Don't lose this code", needles)
        self.assertFalse([n for n in needles if "\\" in n or "x50" in n or "u0043" in n], needles)

    def test_a_malformed_escape_fails_closed(self) -> None:
        for bad in ("\\xZ1", "\\u12", "\\u{}", "\\u{110000}", "\\u{12"):
            with self.subTest(escape=bad):
                r2 = R2 + f"const e = 'Redeem {bad} prepaid';\n"
                with self.assertRaisesRegex(GATE.GateError, "malformed Dart escape"):
                    GATE.derive_needles(make_repo(self.root / f"r{len(bad)}{bad[-1]}", r2=r2))

    def test_quotes_and_braces_inside_an_interpolation_do_not_end_the_literal(self) -> None:
        # R23 A-2: Dart lets `${...}` hold its own string literals. A `//` or `}`
        # inside one must not end the outer literal, open a comment, or invert
        # the quote state and hide every needle after it.
        r2 = R2 + (
            "final h = '${x.replaceAll('//', '')}'; final i = _tr('Prepaid Card Redemption');\n"
            "final j = '${x.split('}')} text'; const k = 'Redeem a Prepaid voucher';\n"
            "final l = '${x /* ' */ + y}'; const m = 'Referral reward granted';\n"
            "final n = \"${{'a': '}'}['a']}\"; const o = 'Promo campaign ended';\n"
        )
        needles, _ = GATE.derive_needles(make_repo(self.root / "r", r2=r2))
        for expected in (
            "Prepaid Card Redemption",
            "Redeem a Prepaid voucher",
            "Referral reward granted",
            "Promo campaign ended",
        ):
            self.assertIn(expected, needles)
        self.assertFalse([n for n in needles if "$" in n or "replaceAll" in n], needles)

    def test_a_constant_literal_inside_an_interpolation_is_a_needle(self) -> None:
        # The nested literal is compiled as its own constant, so it can reach the
        # snapshot even though the outer literal is a concatenation.
        main = MAIN.replace(
            "          'Promo bonus days added: {days}':\n",
            "          'Gift ${label('Nested block text')}':\n"
            "              'Burmese gift',\n"
            "          'Promo bonus days added: {days}':\n",
        )
        r2 = R2 + "final p = 'Card: ${_fmt('Voucher code accepted')} ok';\n"
        needles, _ = GATE.derive_needles(make_repo(self.root / "r", main=main, r2=r2))
        self.assertIn("Nested block text", needles)
        self.assertIn("Burmese gift", needles)
        self.assertIn("Voucher code accepted", needles)
        self.assertNotIn("Gift ${label('Nested block text')}", needles)
        self.assertIn("Promo bonus days added: {days}", needles)

    def test_adjacent_and_raw_tr_literals_become_the_compiled_text(self) -> None:
        # R24 V2 finding 3: Dart compiles adjacent literals into one string, so a
        # keyword split across them, or a raw `_tr(r'...')` without a keyword,
        # used to yield no needle at all. Each part stays a needle as before.
        r2 = R2 + (
            "const q = 'Enter your pre'\n    'paid card code';\n"
            "const s = 'Redeem your gift card ' '$name';\n"
            "Widget tr() => Text(_tr(r'Enter the code printed on the card'))"
            " + Text(_tr('Scan the code ' /* a comment */ r'on the back'));\n"
        )
        needles, _ = GATE.derive_needles(make_repo(self.root / "r", r2=r2))
        self.assertIn("Enter your prepaid card code", needles)
        self.assertIn("Enter the code printed on the card", needles)
        self.assertIn("Scan the code on the back", needles)
        self.assertIn("Scan the code ", needles)
        # A part next to an interpolation keeps its own needle; the whole is not
        # a constant and is never one.
        self.assertIn("Redeem your gift card ", needles)
        self.assertFalse([n for n in needles if "$" in n], needles)
        self.assertEqual(
            GATE.literals("final a = 'x' 'y' \"z\";"), ["x", "y", "z", "xyz"]
        )

    def test_blank_comments_keeps_code_after_an_interpolated_literal(self) -> None:
        text = "final a = '${x.replaceAll('//', '')}'; final b = _tr('Kept');"
        self.assertEqual(GATE.blank_comments(text), text)
        text = "final a = r'${'; // comment\nfinal b = 'Kept';"
        self.assertEqual(GATE.literals(text), ["${", "Kept"])

    def test_a_lone_surrogate_needle_is_searched_as_its_code_unit(self) -> None:
        self.assertEqual(GATE._encodings("\ud83d"), [b"\x3d\xd8"])


class ScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = make_repo(self.root / "r")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_gate(self, *aabs: Path) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            rc = GATE.main(["--repo", str(self.repo), *map(str, aabs)])
        return rc, out.getvalue()

    def test_clean_aab_passes(self) -> None:
        aab = make_aab(self.root / "a.aab", b"\x00Hello\x00referral_code\x00Close\x00")
        rc, out = self.run_gate(aab)
        self.assertEqual(rc, 0, out)
        self.assertIn("ANDROID PLAY REDEMPTION GATE: PASS", out)
        self.assertIn("excluded (pinned, used outside the R2 sources): referral_code", out)

    def test_utf8_needle_fails(self) -> None:
        aab = make_aab(self.root / "a.aab", b"..Redeem a Prepaid Card..")
        rc, out = self.run_gate(aab)
        self.assertEqual(rc, 1)
        self.assertIn("FOUND a.aab!base/lib/arm64-v8a/libapp.so: Redeem a Prepaid Card", out)

    def test_utf16_burmese_needle_fails(self) -> None:
        payload = b"xx" + "ကလေး".encode("utf-16-le") + b"yy"
        aab = make_aab(self.root / "a.aab", payload)
        rc, out = self.run_gate(aab)
        self.assertEqual(rc, 1)
        self.assertIn("hits=1", out)

    def test_latin1_needle_fails(self) -> None:
        payload = b"xx" + "Promo café redemption".encode("latin-1") + b"yy"
        repo = make_repo(
            self.root / "lat",
            r2=R2 + "const e = 'Promo café redemption';\n",
        )
        out = io.StringIO()
        with redirect_stdout(out):
            rc = GATE.main(["--repo", str(repo), str(make_aab(self.root / "lat.aab", payload))])
        self.assertEqual(rc, 1, out.getvalue())
        self.assertIn("Promo café redemption", out.getvalue())

    def test_every_libapp_member_and_aab_is_scanned(self) -> None:
        clean = make_aab(self.root / "clean.aab", b"clean")
        dirty = make_aab(
            self.root / "dirty.aab", b"Promo bonus days added: {days}",
            member="base/lib/x86_64/libapp.so",
        )
        rc, out = self.run_gate(clean, dirty)
        self.assertEqual(rc, 1)
        self.assertIn("dirty.aab!base/lib/x86_64/libapp.so", out)

    def test_non_libapp_members_are_scanned(self) -> None:
        aab = make_aab(
            self.root / "a.aab", b"clean libapp",
            extra=(("base/assets/flutter_assets/r2.json", b"Redeem a Prepaid Card"),
                   ("base/dex/classes.dex", b"\x00")),
        )
        rc, out = self.run_gate(aab)
        self.assertEqual(rc, 1)
        self.assertIn("FOUND a.aab!base/assets/flutter_assets/r2.json: Redeem a Prepaid Card", out)

    def test_a_root_level_libapp_member_is_scanned(self) -> None:
        aab = make_aab(self.root / "a.aab", b"clean libapp",
                       extra=(("libapp.so", b"Redeem a Prepaid Card"),))
        rc, out = self.run_gate(aab)
        self.assertEqual(rc, 1)
        self.assertIn("FOUND a.aab!libapp.so", out)

    def test_aab_without_libapp_fails_closed(self) -> None:
        aab = make_aab(self.root / "a.aab", b"", member="")
        rc, out = self.run_gate(aab)
        self.assertEqual(rc, 1)
        self.assertIn("has no libapp.so", out)

    def test_hits_survive_an_unreadable_later_aab(self) -> None:
        dirty = make_aab(self.root / "dirty.aab", b"Redeem a Prepaid Card")
        broken = make_aab(self.root / "broken.aab", b"", member="")
        rc, out = self.run_gate(dirty, broken)
        self.assertEqual(rc, 1)
        self.assertIn("FOUND dirty.aab!base/lib/arm64-v8a/libapp.so: Redeem a Prepaid Card", out)
        self.assertIn("ERROR ", out)
        self.assertIn("broken.aab has no libapp.so", out)
        self.assertIn("errors=1", out)

    def test_a_missing_aab_fails_closed(self) -> None:
        rc, out = self.run_gate(self.root / "absent.aab")
        self.assertEqual(rc, 1)
        self.assertIn("ANDROID PLAY REDEMPTION GATE: FAIL", out)

    def test_an_escaped_needle_is_found_in_its_compiled_form(self) -> None:
        self.repo = make_repo(
            self.root / "esc", r2=R2 + "const e = 'Gift card \\u{1F381} redeemed';\n",
        )
        payload = b"xx" + "Gift card \U0001F381 redeemed".encode("utf-16-le") + b"yy"
        rc, out = self.run_gate(make_aab(self.root / "a.aab", payload))
        self.assertEqual(rc, 1, out)
        self.assertIn("hits=1", out)

    def test_an_understated_member_size_is_inflated_in_bounded_steps(self) -> None:
        # The central directory claims 4096 bytes for 8 MiB of deflated data.
        # The gate must fail on the CRC without asking zlib for more than one
        # bounded step at a time (archive.read() asks for up to 2 GiB).
        aab = self.root / "bomb.aab"
        with zipfile.ZipFile(aab, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("base/lib/arm64-v8a/libapp.so", b"clean")
            archive.writestr("base/assets/big.bin", b"\0" * (8 * 1024 * 1024))
        understate_member_size(aab, "base/assets/big.bin", 4096)
        requested: list[int] = []
        real = zipfile._get_decompressor

        class Spy:
            def __init__(self, inner: object) -> None:
                self._inner = inner

            def decompress(self, data: bytes, max_length: int = 0) -> bytes:
                requested.append(max_length)
                return self._inner.decompress(data, max_length)

            def __getattr__(self, name: str) -> object:
                return getattr(self._inner, name)

        with mock.patch.object(
            zipfile, "_get_decompressor", side_effect=lambda kind: Spy(real(kind))
        ):
            rc, out = self.run_gate(aab)
        self.assertEqual(rc, 1, out)
        self.assertIn("Bad CRC-32", out)
        self.assertTrue(requested)
        self.assertLessEqual(max(requested), GATE.READ_CHUNK, requested)

    @unittest.skipUnless(_has_lzma(), "this interpreter has no lzma module")
    def test_a_member_with_another_codec_fails_closed(self) -> None:
        aab = self.root / "lzma.aab"
        with zipfile.ZipFile(aab, "w") as archive:
            archive.writestr("base/lib/arm64-v8a/libapp.so", b"clean")
            archive.writestr("base/assets/r2.json", b"Redeem a Prepaid Card",
                             compress_type=zipfile.ZIP_LZMA)
        rc, out = self.run_gate(aab)
        self.assertEqual(rc, 1, out)
        self.assertIn("uses unsupported zip compression method 14", out)


if __name__ == "__main__":
    unittest.main()
