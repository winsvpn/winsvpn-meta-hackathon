#!/usr/bin/env python3
"""Release gate S14A: Google Play AABs must not carry R2 prepaid, promo or referral redemption text.

R2 (in-app prepaid card redemption with optional promo and referral codes) ships only in
direct-distribution builds: Apple App Review 3.1.1 and the Google Play Payments policy. Play
builds pass --dart-define=WINS_GOOGLE_PLAY_BUILD=true, which makes the redemption code and its
translations unreachable at compile time, so the AOT snapshot (libapp.so) must not contain
their strings. Dart obfuscation renames identifiers, never string literals, so a string that
reaches libapp.so is findable here.

Needles:
  * every key and value of the Play-excluded translation block in lib/main.dart (the
    `if (!_googlePlayBuild) ...<String, String>{` spread inside the localization map);
  * every constant string literal in lib/prepaid_redemption.dart of at least six characters
    that names a redemption (redeem, prepaid, promo, referral, gift, voucher), plus every
    literal passed to `_tr(` there, which is the dialog's only route to visible text.
An interpolated literal is never a needle: Dart compiles `'$x'` to a concatenation, so the
source text `$x` cannot appear in a snapshot.

A needle is dropped only if it is on the pinned ALLOWED_EXCLUDED list. Deriving that set from
"some file in lib/ also contains the literal" is unsound: a comment, dead code, or one live
`_t('Redeem a Prepaid Card')` call site would silently drop the needle and the gate would pass
an artifact that carries the text. Anything not on the list is searched, and a new overlap
turns the gate red for review instead of shrinking it.

Each needle is searched in UTF-8, Latin-1 (Dart one-byte strings) and UTF-16LE (Dart two-byte
strings) in every member of every AAB given, because R2 text can also ride in an asset, a
resource table or a dex member rather than in libapp.so.

An .aab is only ever a Play upload. Garbled Winn engines ship only in the website APK
(owner ruling 2026-10-27), so every libwinnengine.so inside an .aab must still carry the
plain winn3 package path; a garbled engine in a bundle is a FAIL.

Usage: android_play_redemption_gate.py --repo REPO AAB [AAB ...]
Prints ANDROID PLAY REDEMPTION GATE: PASS ... and exits 0, or FAIL lines and exits 1.
"""
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

BLOCK_OPEN = "        if (!_googlePlayBuild) ...<String, String>{"
BLOCK_CLOSE = "        },"
R2_DART = "lib/prepaid_redemption.dart"
R2_METHODS = (
    "  void _showPaymentOptions(BuildContext context) {",
    "  Future<void> _showPrepaidRedemption() async {",
    # Owner ruling 2026-10-24: in-app redemption's own entry, now that the
    # premium button opens the website. It returns on `_googlePlayBuild` first.
    "  List<Widget> _prepaidRedemptionEntries({required double tvOrder}) {",
)
REDEMPTION_RE = re.compile(r"redeem|prepaid|promo|referral|gift|voucher", re.I)
# Matches up to the opening quote of a `_tr(` literal, raw or not; the literal itself
# is read by _read_literal so its escapes decode the way Dart compiles them.
TR_RE = re.compile(r"_tr\(\s*[rR]?(?=['\"])")
MIN_LEN = 6
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
READ_CHUNK = 1024 * 1024
# Pinned: an R2-shaped literal that legitimately ships in Play builds. A new
# entry here is a reviewed decision, never something the scanner may infer.
ALLOWED_EXCLUDED = frozenset({
    # Pre-R2 account API field, read by the account-status code in Play builds.
    "referral_code",
    # Shared button labels: the redemption dialog routes them through `_tr`, but
    # Play-visible screens use the same two words (lib/main.dart keeps their
    # Burmese entries outside the Play-excluded block on purpose).
    "Copy",
    "Close",
})

_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
    "0": "\0", "\\": "\\", "'": "'", '"': '"', "$": "$",
}
_IDENT = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
)


class GateError(Exception):
    pass


def _is_raw_prefix(text: str, i: int) -> bool:
    """True when the character before the quote at `i` makes it a raw literal."""
    return (
        i > 0
        and text[i - 1] in "rR"
        and (i < 2 or text[i - 2] not in _IDENT)
    )


def _block_comment_end(text: str, i: int) -> int:
    """Return the index just past the block comment opening at `i` (Dart nests them)."""
    n, depth, j = len(text), 1, i + 2
    while j < n and depth:
        if text.startswith("/*", j):
            depth += 1
            j += 2
        elif text.startswith("*/", j):
            depth -= 1
            j += 2
        else:
            j += 1
    return j


def _interpolation_end(
    text: str, brace: int, nested: list[tuple[int, str, bool]] | None = None
) -> int:
    """Return the index just past the `}` closing the interpolation whose `{` is at `brace`.

    The expression is Dart code: braces nest, and its string literals (which may hold
    their own interpolations) and comments are skipped, so a quote, `//` or `}` inside
    them neither ends the interpolation nor the enclosing literal. Each literal found
    is appended to `nested` as (index, value, is_constant) when a list is given: Dart
    compiles it as its own string, so it can reach the snapshot.
    """
    n, depth, k = len(text), 1, brace + 1
    while k < n:
        if text.startswith("//", k):
            end = text.find("\n", k)
            k = n if end < 0 else end
            continue
        if text.startswith("/*", k):
            k = _block_comment_end(text, k)
            continue
        c = text[k]
        if c in "'\"":
            if nested is None:
                k = _skip_literal(text, k)
            else:
                value, constant, end = _read_literal(text, k, nested)
                nested.append((k, value, constant))
                k = end
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return n


def _skip_literal(text: str, i: int) -> int:
    """Return the index just past the string literal whose quote is at `i`."""
    n = len(text)
    raw = _is_raw_prefix(text, i)
    quote = text[i]
    delim = quote * 3 if text.startswith(quote * 3, i) else quote
    j = i + len(delim)
    while j < n:
        if text.startswith(delim, j):
            return j + len(delim)
        if text[j] == "\\" and not raw:
            j += 2
            continue
        if not raw and text.startswith("${", j):
            j = _interpolation_end(text, j + 1)
            continue
        if text[j] == "\n" and len(delim) == 1:
            return j
        j += 1
    return n


def blank_comments(text: str) -> str:
    """Return `text` with // and /* */ comments blanked, newlines and columns intact.

    Dart block comments nest. Literals are respected, so `//` inside a literal is
    not a comment and a quote inside a comment does not open a literal.
    """
    out: list[str] = []
    i, n, depth = 0, len(text), 0
    while i < n:
        if depth:
            if text.startswith("*/", i):
                depth -= 1
                out.append("  ")
                i += 2
            elif text.startswith("/*", i):
                depth += 1
                out.append("  ")
                i += 2
            else:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if text.startswith("/*", i):
            depth += 1
            out.append("  ")
            i += 2
            continue
        if text[i] in "'\"":
            j = _skip_literal(text, i)
            out.append(text[i:j])
            i = j
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _read_code_point_escape(text: str, j: int) -> tuple[str, int]:
    """Decode the Dart \\xHH, \\uHHHH or \\u{H...} escape whose backslash is at `j`.

    Returns (value, index past the escape). A malformed escape is a Dart compile
    error, so it fails the gate instead of yielding a needle that cannot match.
    """
    if text[j + 1] == "x":
        digits, end, sizes = text[j + 2:j + 4], j + 4, (2,)
    elif text[j + 2:j + 3] == "{":
        close = text.find("}", j + 3)
        if close == -1:
            close = j + 3
        digits, end, sizes = text[j + 3:close], close + 1, range(1, 7)
    else:
        digits, end, sizes = text[j + 2:j + 6], j + 6, (4,)
    if (
        len(digits) not in sizes
        or any(ch not in "0123456789abcdefABCDEF" for ch in digits)
        or int(digits, 16) > 0x10FFFF
    ):
        raise GateError(f"malformed Dart escape in a string literal: {text[j:j + 10]!r}")
    return chr(int(digits, 16)), end


def _read_literal(
    text: str, i: int, nested: list[tuple[int, str, bool]] | None = None
) -> tuple[str, bool, int]:
    """Return (value, is_constant, end index) for the literal whose quote is at `i`.

    Literals inside its interpolations are appended to `nested` when a list is given.
    """
    n = len(text)
    raw = _is_raw_prefix(text, i)
    quote = text[i]
    delim = quote * 3 if text.startswith(quote * 3, i) else quote
    j = i + len(delim)
    buf: list[str] = []
    constant = True
    while j < n:
        if text.startswith(delim, j):
            return "".join(buf), constant, j + len(delim)
        c = text[j]
        if c == "\\" and not raw:
            nxt = text[j + 1:j + 2]
            if nxt in ("x", "u"):
                # The needle must be the string Dart compiles, not the escape's
                # source spelling, or it can never match the snapshot.
                value, j = _read_code_point_escape(text, j)
                buf.append(value)
                continue
            buf.append(_ESCAPES.get(nxt, nxt))
            j += 2
            continue
        if c == "$" and not raw:
            constant = False
            if text[j + 1:j + 2] == "{":
                j = _interpolation_end(text, j + 1, nested)
                continue
        if c == "\n" and len(delim) == 1:
            break
        buf.append(c)
        j += 1
    return "".join(buf), constant, j


def _read_adjacent(
    text: str, i: int, nested: list[tuple[int, str, bool]] | None = None
) -> tuple[list[tuple[int, str, bool]], int]:
    """Read the literal whose quote is at `i` and every literal adjacent to it.

    Dart concatenates string literals separated only by whitespace (comments are
    blanked first) into one string, and that string is what reaches the snapshot.
    Returns ([(index, value, is_constant), ...], end index).
    """
    n = len(text)
    parts: list[tuple[int, str, bool]] = []
    while True:
        value, constant, end = _read_literal(text, i, nested)
        parts.append((i, value, constant))
        if text[end - 1:end] != text[i]:
            return parts, end  # unterminated: nothing follows it
        k = end
        while k < n and text[k] in " \t\r\n":
            k += 1
        if k + 1 < n and text[k] in "rR" and text[k + 1] in "'\"":
            k += 1
        if k >= n or text[k] not in "'\"":
            return parts, end
        i = k


def scan_literals(text: str) -> list[tuple[int, str, bool]]:
    """Return (0-based line, value, is_constant) for every literal in comment-free `text`.

    Adjacent literals yield each part and, when every part is constant, the
    concatenation Dart compiles from them.
    """
    out: list[tuple[int, str, bool]] = []
    i, n, line = 0, len(text), 0
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in "rR" and i + 1 < n and text[i + 1] in "'\"" and (not i or text[i - 1] not in _IDENT):
            i += 1
            continue
        if c in "'\"":
            nested: list[tuple[int, str, bool]] = []
            parts, end = _read_adjacent(text, i, nested)
            for index, value, constant in parts:
                out.append((line + text.count("\n", i, index), value, constant))
            if len(parts) > 1 and all(constant for _, _, constant in parts):
                out.append((line, "".join(value for _, value, _ in parts), True))
            for index, nested_value, nested_constant in nested:
                out.append((line + text.count("\n", i, index), nested_value, nested_constant))
            line += text.count("\n", i, end)
            i = end
            continue
        i += 1
    return out


def literals(text: str) -> list[str]:
    """Every literal value in `text`, comments removed first."""
    return [v for _, v, _ in scan_literals(blank_comments(text))]


def _method_span(lines: list[str], header: str) -> tuple[int, int]:
    starts = [i for i, line in enumerate(lines) if line == header]
    if len(starts) != 1:
        raise GateError(f"expected exactly one method header: {header.strip()}")
    for j in range(starts[0] + 1, len(lines)):
        if lines[j] == "  }":
            return starts[0], j
    raise GateError(f"method has no closing brace: {header.strip()}")


def _block_span(lines: list[str]) -> tuple[int, int, int]:
    """Return (open line, close line, entry count) of the Play-excluded block.

    The close is found by brace depth, not by the first line that looks like a
    closer: a nested spread inside the block would otherwise truncate it and
    silently drop every needle after the truncation point.
    """
    opens = [i for i, line in enumerate(lines) if line == BLOCK_OPEN]
    if len(opens) != 1:
        raise GateError("lib/main.dart must hold exactly one Play-excluded translation block")
    open_i = opens[0]
    text = blank_comments("\n".join(lines[open_i:]))
    depth, entries, end, i, n = 0, 0, None, 0, len(text)
    line_offset = 0
    while i < n:
        c = text[i]
        if c == "\n":
            line_offset += 1
            i += 1
            continue
        if c in "'\"":
            stop = _skip_literal(text, i)
            line_offset += text.count("\n", i, stop)
            i = stop
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = open_i + line_offset
                break
        elif c == ":" and depth == 1:
            entries += 1
        i += 1
    if end is None:
        raise GateError("the Play-excluded translation block is not closed")
    if lines[end] != BLOCK_CLOSE:
        raise GateError(
            "the Play-excluded translation block does not close with "
            f"{BLOCK_CLOSE!r} (found {lines[end]!r})"
        )
    if entries == 0:
        raise GateError("the Play-excluded translation block holds no entries")
    return open_i, end, entries


def derive_needles(repo: Path) -> tuple[list[str], list[str]]:
    """Return (needles, excluded) for the repository's R2 sources."""
    lines = (repo / "lib" / "main.dart").read_text(encoding="utf-8").split("\n")
    open_i, close, _entries = _block_span(lines)
    main_lits = scan_literals(blank_comments("\n".join(lines)))
    candidates = {
        value for line, value, constant in main_lits
        if constant and value and open_i < line < close
    }
    r2_blanked = blank_comments((repo / R2_DART).read_text(encoding="utf-8"))
    candidates |= {
        value for _, value, constant in scan_literals(r2_blanked)
        if constant and len(value) >= MIN_LEN and REDEMPTION_RE.search(value)
    }
    for match in TR_RE.finditer(r2_blanked):
        parts, _end = _read_adjacent(r2_blanked, match.end())
        _index, value, constant = parts[0]
        if constant and value:
            candidates.add(value)
        if len(parts) > 1 and all(part_constant for _, _, part_constant in parts):
            candidates.add("".join(part_value for _, part_value, _ in parts))
    if not candidates:
        raise GateError("no needles derived from the R2 sources")

    r2_spans = [(open_i, close)] + [_method_span(lines, h) for h in R2_METHODS]
    elsewhere = {
        value for line, value, _ in main_lits
        if not any(a <= line <= b for a, b in r2_spans)
    }
    for other in sorted((repo / "lib").rglob("*.dart")):
        rel = other.relative_to(repo).as_posix()
        if rel in ("lib/main.dart", R2_DART):
            continue
        elsewhere |= set(literals(other.read_text(encoding="utf-8")))
    overlap = candidates & elsewhere
    unexpected = sorted(overlap - ALLOWED_EXCLUDED)
    if unexpected:
        raise GateError(
            "R2 literals are also used outside the R2 sources and are not on the pinned "
            "ALLOWED_EXCLUDED list; review each one, then either drop the use from the "
            "Play-build sources or add the literal to ALLOWED_EXCLUDED: "
            f"{[s[:60] for s in unexpected[:10]]}"
        )
    excluded = sorted(overlap)
    needles = sorted(candidates - elsewhere)
    if not needles:
        raise GateError("every derived needle is also used outside the R2 sources")
    return needles, excluded


def _encodings(needle: str) -> list[bytes]:
    # A Dart two-byte string holds UTF-16 code units, so a lone surrogate from a
    # \uD800-style escape is searched as that code unit; it has no UTF-8 form.
    forms = [needle.encode("utf-16-le", "surrogatepass")]
    for codec in ("utf-8", "latin-1"):
        try:
            forms.append(needle.encode(codec))
        except UnicodeEncodeError:
            pass
    return list(dict.fromkeys(forms))


# Present in every plain datapath build; garble hashes it away.
PLAIN_WINN_ENGINE_MARKER = b"winsvpn.local/winnprotocol/winn3/core"


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Inflate one member in READ_CHUNK steps.

    archive.read() lets zlib produce up to 2 GiB per call before the declared
    size truncates it, so a member that understates its size costs that much
    memory before its CRC check fails. Bounded reads keep each step small; the
    declared file_size still caps the result and the CRC is still checked at
    the end of the member.
    """
    parts: list[bytes] = []
    with archive.open(info) as member:
        while chunk := member.read(READ_CHUNK):
            parts.append(chunk)
    return b"".join(parts)


def scan_aab(aab: Path, needles: list[str]) -> tuple[int, list[str]]:
    """Return (scanned member count, hit descriptions) for one AAB."""
    hits: list[str] = []
    with zipfile.ZipFile(aab) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if not any(info.filename.endswith("/libapp.so") for info in infos):
            raise GateError(f"{aab} has no libapp.so")
        scanned = 0
        total = 0
        for info in infos:
            if info.file_size > MAX_MEMBER_BYTES:
                raise GateError(f"{aab}!{info.filename} exceeds the member size bound")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise GateError(f"{aab} exceeds the total size bound")
            # The other zipfile codecs inflate a whole read without a bound,
            # and bundletool writes only stored and deflated members.
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise GateError(
                    f"{aab}!{info.filename} uses unsupported zip compression "
                    f"method {info.compress_type}"
                )
            blob = _read_member(archive, info)
            scanned += 1
            if (
                aab.suffix == ".aab"
                and info.filename.endswith("/libwinnengine.so")
                and PLAIN_WINN_ENGINE_MARKER not in blob
            ):
                hits.append(
                    f"{aab.name}!{info.filename}: garbled website-only Winn engine in a Play bundle"
                )
            for needle in needles:
                if any(form in blob for form in _encodings(needle)):
                    hits.append(f"{aab.name}!{info.filename}: {needle[:80]}")
    return scanned, hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("aabs", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        needles, excluded = derive_needles(args.repo)
    except (GateError, OSError, UnicodeDecodeError) as exc:
        print(f"ANDROID PLAY REDEMPTION GATE: FAIL: {exc}")
        return 1
    errors: list[str] = []
    hits: list[str] = []
    members = 0
    for aab in args.aabs:
        try:
            count, found = scan_aab(aab, needles)
        except (GateError, OSError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
            # Keep scanning: an unreadable artifact must not hide the evidence
            # already collected from a readable one.
            errors.append(str(exc))
            continue
        members += count
        hits.extend(found)
    for needle in excluded:
        print(f"excluded (pinned, used outside the R2 sources): {needle[:80]}")
    for hit in hits:
        print(f"FOUND {hit}")
    for error in errors:
        print(f"ERROR {error}")
    status = "FAIL" if hits or errors else "PASS"
    print(
        f"ANDROID PLAY REDEMPTION GATE: {status} needles={len(needles)} "
        f"excluded={len(excluded)} aabs={len(args.aabs)} members_scanned={members} "
        f"hits={len(hits)} errors={len(errors)}"
    )
    return 1 if status == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
