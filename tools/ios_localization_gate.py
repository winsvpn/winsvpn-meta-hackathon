#!/usr/bin/env python3
"""Enforce a single source of truth for the iOS localization declaration.

`CFBundleLocalizations` in `ios/Runner/Info.plist` and `kSupportedLocales` in
`lib/locale_resolution.dart` must agree. When they drift, iOS intersects the
user's language list with the bundle's declared localizations to build
`NSLocale.preferredLanguages`; a mismatch silently pins the app to whatever the
plist lists (or to the development region), independent of what Dart can serve.

The Dart list is the authority. This script only READS `locale_resolution.dart`
(it is owned by another lane) and treats `kSupportedLocales` as the spec, then
either verifies or regenerates the plist from it.

Usage:
    python3 tools/ios_localization_gate.py --check
        Exit 0 when CFBundleLocalizations matches kSupportedLocales, exit 1 with
        a diff otherwise. Intended as the regression gate in CI.
    python3 tools/ios_localization_gate.py --update
        Rewrite the CFBundleLocalizations array in Info.plist to match
        kSupportedLocales. A targeted textual edit: every other key and the
        explanatory comment are preserved exactly.

The source of truth is `kSupportedLocales`, so this script never judges "is the
Dart list correct" (that is the lane that owns the file); it only keeps the plist
and the list from contradicting each other.

Optional overrides to point at non-default files are for self-testing only; the
defaults are the real in-repo paths.
"""

import argparse
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DART = os.path.join(REPO_ROOT, "lib", "locale_resolution.dart")
DEFAULT_PLIST = os.path.join(REPO_ROOT, "ios", "Runner", "Info.plist")

_PLIST_KEY = "<key>CFBundleLocalizations</key>"
_ARRAY_OPEN = "<array>"
_ARRAY_CLOSE = "</array>"
_STRING_RE = re.compile(r"<string>\s*([^<\s]+?)\s*</string>")


def _fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def supported_language_codes(dart_path):
    """The ordered, de-duplicated list of language codes kSupportedLocales declares."""
    with open(dart_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    marker = "kSupportedLocales = <Locale>["
    start = text.find(marker)
    if start == -1:
        _fail("could not find kSupportedLocales declaration in %s" % dart_path)
    block_start = text.find("[", start)
    # Find the closing bracket that balances the one that opens the list. The
    # body is only Locale(...) calls, so the first ']' after the opening '[' is
    # the terminator.
    end = text.find("]", block_start)
    if end == -1:
        _fail("could not find the end of kSupportedLocales in %s" % dart_path)
    block = text[block_start:end]
    codes = []
    seen = set()
    for match in re.finditer(r"Locale\(\s*'([A-Za-z0-9_]+)'", block):
        code = match.group(1)
        if code not in seen:
            seen.add(code)
            codes.append(code)
    if not codes:
        _fail("kSupportedLocales in %s declares no Locale entries" % dart_path)
    return codes


def plist_language_codes(plist_path):
    with open(plist_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    key_at = text.find(_PLIST_KEY)
    if key_at == -1:
        _fail("Info.plist has no %s key" % _PLIST_KEY)
    array_at = text.find(_ARRAY_OPEN, key_at)
    if array_at == -1:
        _fail("CFBundleLocalizations in %s is not an <array>" % plist_path)
    close_at = text.find(_ARRAY_CLOSE, array_at)
    if close_at == -1:
        _fail("unterminated CFBundleLocalizations array in %s" % plist_path)
    body = text[array_at:close_at]
    return [m for m in (_STRING_RE.findall(body))]


def _write_plist_array(plist_path, codes):
    with open(plist_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    key_at = text.find(_PLIST_KEY)
    array_at = text.find(_ARRAY_OPEN, key_at)
    close_at = text.find(_ARRAY_CLOSE, array_at)
    if -1 in (key_at, array_at, close_at):
        _fail("could not locate CFBundleLocalizations array in %s" % plist_path)
    indent = "\t\t"
    body = "\n".join("%s<string>%s</string>" % (indent, c) for c in codes)
    # <array>\n  <string>..</string>\n\t</array> — only the inner entries change.
    new_array = "%s\n%s\n\t" % (_ARRAY_OPEN, body)
    close_old = text.index(_ARRAY_CLOSE, array_at)
    replaced_len = close_old + len(_ARRAY_CLOSE) - array_at
    updated = text[:array_at] + new_array + _ARRAY_CLOSE + text[array_at + replaced_len:]
    with open(plist_path, "w", encoding="utf-8") as fh:
        fh.write(updated)


def _diff_summary(want, have):
    want_set, have_set = set(want), set(have)
    lines = []
    missing = want_set - have_set
    extra = have_set - want_set
    if missing:
        lines.append("  in kSupportedLocales but MISSING from plist: %s"
                     % ", ".join(sorted(missing)))
    if extra:
        lines.append("  in plist but NOT declared by kSupportedLocales: %s"
                     % ", ".join(sorted(extra)))
    if not lines:
        lines.append("  same language codes, different order: want %s have %s"
                     % (want, have))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit 0 if plist matches kSupportedLocales, else 1")
    parser.add_argument("--update", action="store_true",
                        help="rewrite CFBundleLocalizations to match")
    parser.add_argument("--dart", default=DEFAULT_DART)
    parser.add_argument("--plist", default=DEFAULT_PLIST)
    args = parser.parse_args()

    if args.check == args.update:
        _fail("pass exactly one of --check or --update")

    want = supported_language_codes(args.dart)
    have = plist_language_codes(args.plist)

    if args.update:
        if want == have:
            print("CFBundleLocalizations already matches kSupportedLocales: %s"
                  % ", ".join(want))
            return
        _write_plist_array(args.plist, want)
        after = plist_language_codes(args.plist)
        if after != want:
            _fail("update wrote %s; expected %s" % (after, want))
        print("updated CFBundleLocalizations to %s" % ", ".join(want))
        return

    if want == have:
        print("OK: CFBundleLocalizations matches kSupportedLocales: %s"
              % ", ".join(want))
        return
    print("MISMATCH between CFBundleLocalizations and kSupportedLocales:\n%s"
          % _diff_summary(want, have))
    sys.exit(1)


if __name__ == "__main__":
    main()
