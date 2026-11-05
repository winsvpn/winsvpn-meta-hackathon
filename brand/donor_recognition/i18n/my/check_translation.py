#!/usr/bin/env python3
"""Mechanical verification of a completed Burmese donor-letter translation.

    python3 check_translation.py donor-letter.my.csv

Nothing here judges meaning. It checks the things a human reviewer reads past:
that every figure survived, that no Burmese numeral leaked in, that the caveat
and the disclaimers are still present as text, that no EIN or street address
appeared, and that nothing is still sitting in English.

The previous machine-translation attempt leaked Burmese numerals into a segment
despite an explicit instruction to keep Western Arabic digits. That class of
defect is caught here by codepoint, not by eye.

Exit status 0 only if there are zero FAILs. Warnings do not fail the run but
every one of them wants a human answer before publishing.

No model is loaded. No network. Reads only the two files named on the command
line (or their defaults).
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import pathlib
import re
import sys
import unicodedata

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_PKG = HERE / "donor-letter.segments.json"

MERGED = "MERGED"          # marker: this sentence was folded into a neighbour

# --------------------------------------------------------------------------
# 1. The figure manifest. Hard-coded on purpose: it is the list the owner
#    signed off on, not a list derived from whatever the file happens to say.
#    scope "*" means anywhere in the translation; otherwise the figure must
#    appear inside that specific block, which is what makes the check mean
#    something (a bare "5" anywhere would prove nothing).
# --------------------------------------------------------------------------
REQUIRED = [
    ("AGI ceiling for cash gifts",        r"(?<![\d,.])60\s?%",      "ceil.body"),
    ("carryforward, in years",            r"(?<![\d,.])5(?![\d,.%])", "ceil.body"),
    ("non-itemizer deduction, single",    r"\$\s?1,000",             "callout.body"),
    ("non-itemizer deduction, joint",     r"\$\s?2,000",             "callout.body"),
    ("AGI floor, new for 2026",           r"(?<![\d,.])0\.5\s?%",    "arith.body"),
    ("standard deduction, single",        r"\$\s?16,100",            "callout.body"),
    ("standard deduction, joint",         r"\$\s?32,200",            "callout.body"),
    ("standard deduction, head of house", r"\$\s?24,150",            "callout.body"),
    ("acknowledgment threshold",          r"\$\s?250",               "ack.body"),
    ("tax year, in the callout",          r"(?<![\d,.])2026(?![\d,.])", "callout.body"),
    ("tax year, letterhead pill",         r"(?<![\d,.])2026(?![\d,.])", "hdr.taxyear"),
    ("tax year, subtitle",                r"(?<![\d,.])2026(?![\d,.])", "ttl.sub"),
    ("AGI floor also stated in the box",  r"(?<![\d,.])0\.5\s?%|\$\s?1,000", "callout.body"),
    ("ceilings for non-cash gifts",       r"50\s?%",                 "ceil.body"),
    ("the four illustrated gifts",        r"\$\s?100,000",           "*"),
]

# --------------------------------------------------------------------------
# 2. Character-level prohibitions.
# --------------------------------------------------------------------------
# Myanmar digits U+1040-1049, Shan U+1090-1099, Mon/other Myanmar-block digits.
MYANMAR_DIGITS = set(range(0x1040, 0x104A)) | set(range(0x1090, 0x109A))
# Em dash, en dash, horizontal bar, figure dash, minus sign, full/small variants.
LONG_DASHES = {0x2014, 0x2013, 0x2015, 0x2012, 0x2212, 0xFE58, 0xFE63, 0xFF0D,
               0x2E3A, 0x2E3B, 0x2010, 0x2011}
EIN_RE = re.compile(r"\b\d{2}-\d{7}\b")
ADDRESS_RE = re.compile(
    r"\b(?:P\.?\s?O\.?\s?Box|Suite|Ste\.|Apt\.|\d+\s+[A-Z][a-z]+\s+"
    r"(?:Street|St\.|Avenue|Ave\.|Road|Rd\.|Drive|Dr\.|Lane|Ln\.|Boulevard|"
    r"Blvd\.|Way|Court|Ct\.|Place|Pl\.))\b")
MYANMAR_BLOCK = re.compile(r"[က-႟ꩠ-ꩿꧠ-꧿]")
FIGURE_RE = re.compile(r"\$?\d{1,3}(?:,\d{3})+(?:\.\d+)?%?|\$?\d+(?:\.\d+)?%?")


class Report:
    def __init__(self) -> None:
        self.fails: list[str] = []
        self.warns: list[str] = []
        self.infos: list[str] = []
        self.checks = 0

    def check(self, ok: bool, msg: str, warn: bool = False) -> bool:
        self.checks += 1
        if not ok:
            (self.warns if warn else self.fails).append(msg)
        return ok

    def fail(self, msg: str) -> None:
        self.checks += 1
        self.fails.append(msg)

    def warn(self, msg: str) -> None:
        self.checks += 1
        self.warns.append(msg)

    def info(self, msg: str) -> None:
        self.infos.append(msg)


def load_targets(path: pathlib.Path) -> dict[str, str]:
    """Accept the translator CSV or a plain {id: burmese} JSON."""
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "segment_list" in raw:
            return {s["id"]: (s.get("target_my") or "")
                    for s in raw["segment_list"]}
        return {str(k): (v or "") for k, v in raw.items()}
    out: dict[str, str] = {}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            sid = (row.get("id") or "").strip()
            if sid:
                out[sid] = (row.get("burmese_translation") or "").strip()
    return out


def describe_chars(s: str, codes: set[int]) -> str:
    seen = []
    for ch in s:
        if ord(ch) in codes and ch not in [c for c, _ in seen]:
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = "?"
            seen.append((ch, "U+%04X %s" % (ord(ch), name)))
    return "; ".join("%r = %s" % (c, n) for c, n in seen)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("translation", nargs="?", default=str(HERE /
                    "donor-letter.my.csv"),
                    help="completed translator CSV (or a {id: text} JSON)")
    ap.add_argument("--package", default=str(DEFAULT_PKG),
                    help="donor-letter.segments.json")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="do not fail on empty targets (use while translating)")
    args = ap.parse_args()

    pkg = json.loads(pathlib.Path(args.package).read_text(encoding="utf-8"))
    segs = {s["id"]: s for s in pkg["segment_list"]}
    tpath = pathlib.Path(args.translation)
    if not tpath.exists():
        print("FAIL  translation file not found: %s" % tpath)
        return 2
    targets = load_targets(tpath)

    r = Report()
    print("package    : %s" % args.package)
    print("translation: %s" % tpath)
    print("segments   : %d expected, %d supplied" % (len(segs), len(targets)))
    print()

    # ---- structure ------------------------------------------------------
    missing_ids = sorted(set(segs) - set(targets))
    extra_ids = sorted(set(targets) - set(segs))
    r.check(not missing_ids, "STRUCTURE: %d segment ids absent from the "
            "translation file: %s" % (len(missing_ids), missing_ids[:12]))
    r.check(not extra_ids, "STRUCTURE: unknown segment ids in the translation "
            "file: %s" % extra_ids[:12])

    blocks_en: dict[str, list[str]] = collections.defaultdict(list)
    blocks_my: dict[str, list[str]] = collections.defaultdict(list)
    for sid, s in segs.items():
        blocks_en[s["block"]].append(s["source_en"])
        blocks_my[s["block"]].append(targets.get(sid, ""))
    en_text = {b: " ".join(v) for b, v in blocks_en.items()}
    my_text = {b: " ".join(t for t in v if t.strip().upper() != MERGED)
               for b, v in blocks_my.items()}
    all_my = " ".join(my_text.values())

    # ---- completeness ---------------------------------------------------
    empty = [sid for sid, s in sorted(segs.items())
             if not targets.get(sid, "").strip()]
    if empty:
        msg = ("COMPLETENESS: %d segments have no Burmese text: %s"
               % (len(empty), ", ".join(empty[:20])
                  + (" ..." if len(empty) > 20 else "")))
        r.warn(msg) if args.allow_incomplete else r.fail(msg)
    else:
        r.check(True, "")

    for bid, parts in blocks_my.items():
        live = [p for p in parts if p.strip()
                and p.strip().upper() != MERGED]
        if any(p.strip().upper() == MERGED for p in parts) and not live:
            r.fail("COMPLETENESS: block %s is entirely MERGED, so its meaning "
                   "is nowhere in the translation" % bid)

    # ---- verbatim segments ---------------------------------------------
    for sid, s in sorted(segs.items()):
        if s["kind"] in ("verbatim", "figure"):
            got = targets.get(sid, "")
            r.check(got.strip() == s["source_en"].strip(),
                    "VERBATIM: segment %s (%s) must be reproduced exactly.\n"
                    "        expected %r\n        got      %r"
                    % (sid, s["block"], s["source_en"], got))

    # ---- non-ASCII digits, the numeral leak --------------------------------
    for sid in sorted(targets):
        t = targets[sid]
        bad = {ord(ch) for ch in t
               if unicodedata.category(ch) == "Nd" and not ch.isascii()}
        if bad:
            r.fail("NUMERALS: segment %s contains non-Western digits: %s\n"
                   "        text: %s" % (sid, describe_chars(t, bad), t))
        mm = {ord(ch) for ch in t if ord(ch) in MYANMAR_DIGITS}
        if mm and not bad:
            r.fail("NUMERALS: segment %s contains Myanmar-block digits: %s"
                   % (sid, describe_chars(t, mm)))
    if not any(f.startswith("NUMERALS") for f in r.fails):
        r.check(True, "")

    # ---- long dashes -----------------------------------------------------
    for sid in sorted(targets):
        t = targets[sid]
        bad = {ord(ch) for ch in t if ord(ch) in LONG_DASHES}
        if bad:
            r.fail("DASHES: segment %s contains a long dash: %s"
                   % (sid, describe_chars(t, bad)))
    if not any(f.startswith("DASHES") for f in r.fails):
        r.check(True, "")

    # ---- required figure manifest ---------------------------------------
    print("Required figures")
    print("-" * 72)
    for label, pattern, scope in REQUIRED:
        hay = all_my if scope == "*" else my_text.get(scope, "")
        ok = bool(re.search(pattern, hay))
        r.check(ok, "REQUIRED FIGURE missing: %s (/%s/ not found in %s)"
                % (label, pattern, "the whole translation" if scope == "*"
                   else "block " + scope))
        print("  %-4s %-36s %s" % ("ok" if ok else "MISS", label,
                                   scope if scope != "*" else "anywhere"))
    print()

    # ---- per-block figure preservation ----------------------------------
    for bid in sorted(en_text):
        want = collections.Counter(FIGURE_RE.findall(en_text[bid]))
        got = collections.Counter(FIGURE_RE.findall(my_text.get(bid, "")))
        lost = {f: n - got.get(f, 0) for f, n in want.items()
                if got.get(f, 0) < n}
        if lost:
            r.fail("FIGURES: block %s lost %s\n        en: %s\n        my: %s"
                   % (bid, ", ".join("%s (x%d)" % (f, n)
                                     for f, n in sorted(lost.items())),
                      en_text[bid][:160], my_text.get(bid, "")[:160]))
    if not any(f.startswith("FIGURES") for f in r.fails):
        r.check(True, "")

    # ---- currency and percent symbols ------------------------------------
    for bid in sorted(en_text):
        for sym in ("$", "%"):
            a, b = en_text[bid].count(sym), my_text.get(bid, "").count(sym)
            if b < a:
                r.fail("SYMBOLS: block %s has %d '%s' in English but %d in "
                       "Burmese" % (bid, a, sym, b))
    if not any(f.startswith("SYMBOLS") for f in r.fails):
        r.check(True, "")

    # ---- things that must never appear ----------------------------------
    for sid in sorted(targets):
        if EIN_RE.search(targets[sid]):
            r.fail("DISCLOSURE: segment %s looks like it contains an EIN. No "
                   "EIN goes on a public web surface." % sid)
        if ADDRESS_RE.search(targets[sid]):
            r.fail("DISCLOSURE: segment %s looks like it contains a street "
                   "address. None goes on a public web surface." % sid)
    if not any(f.startswith("DISCLOSURE") for f in r.fails):
        r.check(True, "")

    # ---- still in English? -----------------------------------------------
    untranslated = []
    identical = []
    for sid, s in sorted(segs.items()):
        if s["kind"] in ("verbatim", "figure"):
            continue
        t = targets.get(sid, "").strip()
        if not t or t.upper() == MERGED:
            continue
        if not MYANMAR_BLOCK.search(t):
            untranslated.append(sid)
        elif t == s["source_en"].strip():
            identical.append(sid)
    r.check(not untranslated,
            "UNTRANSLATED: %d segments contain no Burmese script at all: %s"
            % (len(untranslated), ", ".join(untranslated[:20])))
    if identical:
        r.warn("IDENTICAL: %d segments equal the English source: %s"
               % (len(identical), ", ".join(identical[:20])))

    # ---- informational ---------------------------------------------------
    zwsp = sum(t.count("​") for t in targets.values())
    if zwsp:
        r.info("%d zero-width spaces (U+200B) in the translation. Legitimate "
               "in Burmese as word hints; Chrome will break at them, which "
               "can produce short lines. Layout is measured, so this is "
               "reported rather than rejected." % zwsp)
    nbsp = sum(t.count(" ") for t in targets.values())
    if nbsp:
        r.info("%d non-breaking spaces (U+00A0) present." % nbsp)
    filled = sum(1 for sid, s in segs.items()
                 if targets.get(sid, "").strip()
                 and s["kind"] not in ("verbatim", "figure"))
    total = sum(1 for s in segs.values()
                if s["kind"] not in ("verbatim", "figure"))
    r.info("%d of %d translatable segments filled." % (filled, total))

    # ---- report ----------------------------------------------------------
    print("Result")
    print("-" * 72)
    for m in r.infos:
        print("INFO  %s" % m)
    for m in r.warns:
        print("WARN  %s" % m)
    for m in r.fails:
        print("FAIL  %s" % m)
    print()
    print("%d checks, %d FAIL, %d WARN" % (r.checks, len(r.fails),
                                           len(r.warns)))
    if r.fails:
        print("\nNOT READY TO PUBLISH.")
        return 1
    print("\nAll mechanical checks passed. This says nothing about whether the "
          "meaning is right;\nthat still needs the human review described in "
          "TRANSLATOR-BRIEF.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
