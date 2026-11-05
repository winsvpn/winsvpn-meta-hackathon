#!/usr/bin/env python3
"""Regenerate the translatable segment package for the donor tax letter.

Source of truth: brand/donor_recognition/donor-tax-deduction-letter.svg

The SVG holds 92 <text> elements, but those are *rendered lines*, not units of
meaning: a single sentence is split across four of them. Translating a rendered
line is how you get a wrong tax document, so this script first regroups the 92
lines into logical blocks, then splits each prose block into sentences. The
sentence is the translation unit and the review unit.

Outputs (all written next to this script):

  donor-letter.segments.json   canonical machine-readable package
  donor-letter.my.csv          the file the human translator types into
  donor-letter.segments.md     readable bilingual worksheet with the notes

Round-trip safety: the script asserts that re-joining every segment of a block
reproduces that block's source text character for character, so no wording can
be silently dropped during segmentation.

No model is loaded. No network. Read-only with respect to the source SVG.
"""
from __future__ import annotations

import csv
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]                      # .../source/wins_vpn
SVG = REPO / "brand" / "donor_recognition" / "donor-tax-deduction-letter.svg"
NS = "{http://www.w3.org/2000/svg}"

# --------------------------------------------------------------------------
# Block map. Each entry regroups rendered <text> indices into one logical block.
#
#   id      stable identifier, used by the builder and the checker
#   kind    prose | heading | label | verbatim | figure
#   idx     indices of the <text> elements in document order
#   join    how the rendered lines recombine ("space" or "none")
#   region  layout region for the Burmese rebuild
# --------------------------------------------------------------------------
BLOCKS = [
    # letterhead band
    ("hdr.org",            "verbatim", [0],            "space", "header"),
    ("hdr.status",         "label",    [1],            "space", "header"),
    ("hdr.exempt",         "label",    [2],            "space", "header"),
    ("hdr.taxyear",        "label",    [3],            "space", "header"),
    # title block
    ("ttl.kicker",         "label",    [4],            "space", "title"),
    ("ttl.title",          "heading",  [5],            "space", "title"),
    ("ttl.sub",            "prose",    [6],            "space", "title"),
    # salutation and opening
    ("body.salutation",    "label",    [7],            "space", "body"),
    ("body.p1",            "prose",    [8],            "space", "body"),
    ("body.p2",            "prose",    [9, 10],        "space", "body"),
    # the caveat box
    ("callout.head",       "heading",  [11],           "space", "callout"),
    ("callout.body",       "prose",    [12, 13, 14, 15, 16], "space", "callout"),
    # arithmetic
    ("arith.head",         "heading",  [17],           "space", "body"),
    ("arith.body",         "prose",    [18, 19, 20],   "space", "body"),
    # table
    ("tbl.head",           "heading",  [21],           "space", "body"),
    ("tbl.col.gift",       "label",    [22],           "space", "table"),
    ("tbl.col.assumptions", "label",   [23],           "space", "table"),
    ("tbl.col.deduct",     "label",    [24, 25],       "space", "table"),
    ("tbl.col.rate",       "label",    [26, 27],       "space", "table"),
    ("tbl.col.reduction",  "label",    [28, 29],       "space", "table"),
    ("tbl.col.netcost",    "label",    [30, 31],       "space", "table"),

    ("row1.gift",          "figure",   [32],           "space", "table"),
    ("row1.assume",        "label",    [33, 34],       "space", "table"),
    ("row1.deduct",        "figure",   [35],           "space", "table"),
    ("row1.note",          "label",    [36],           "space", "table"),
    ("row1.rate",          "figure",   [37],           "space", "table"),
    ("row1.reduction",     "label",    [38],           "space", "table"),
    ("row1.netcost",       "label",    [39],           "space", "table"),

    ("row2.gift",          "figure",   [40],           "space", "table"),
    ("row2.assume",        "label",    [41, 42],       "space", "table"),
    ("row2.deduct",        "figure",   [43],           "space", "table"),
    ("row2.note",          "label",    [44],           "space", "table"),
    ("row2.rate",          "figure",   [45],           "space", "table"),
    ("row2.reduction",     "label",    [46],           "space", "table"),
    ("row2.netcost",       "label",    [47],           "space", "table"),

    ("row3.gift",          "figure",   [48],           "space", "table"),
    ("row3.assume",        "label",    [49, 50],       "space", "table"),
    ("row3.deduct",        "figure",   [51],           "space", "table"),
    ("row3.note",          "label",    [52],           "space", "table"),
    ("row3.rate",          "figure",   [53],           "space", "table"),
    ("row3.reduction",     "label",    [54],           "space", "table"),
    ("row3.netcost",       "label",    [55],           "space", "table"),

    ("row4.gift",          "figure",   [56],           "space", "table"),
    ("row4.assume",        "label",    [57, 58],       "space", "table"),
    ("row4.deduct",        "figure",   [59],           "space", "table"),
    ("row4.note",          "label",    [60],           "space", "table"),
    ("row4.rate",          "figure",   [61],           "space", "table"),
    ("row4.reduction",     "label",    [62],           "space", "table"),
    ("row4.netcost",       "label",    [63],           "space", "table"),

    ("tbl.footnote",       "prose",    [64, 65, 66, 67], "space", "body"),
    # ceilings / carryforward / receipt
    ("ceil.head",          "heading",  [68],           "space", "body"),
    ("ceil.lead",          "label",    [69],           "space", "body"),
    ("ceil.body",          "prose",    [70, 71, 72],   "space", "body"),
    ("ack.lead",           "label",    [73],           "space", "body"),
    ("ack.body",           "prose",    [74, 75, 76],   "space", "body"),
    # limits of the letter
    ("cannot.head",        "heading",  [77],           "space", "body"),
    ("cannot.body",        "prose",    [78, 79, 80],   "space", "body"),
    # signature
    ("sign.closing",       "label",    [81],           "space", "body"),
    ("sign.org",           "verbatim", [82],           "space", "body"),
    ("sign.orgsuffix",     "label",    [83],           "space", "body"),
    # fine print
    ("fine.print",         "prose",    [84, 85, 86, 87, 88, 89, 90], "space", "fine"),
    ("footer.domain",      "verbatim", [91],           "space", "footer"),
]

# --------------------------------------------------------------------------
# Two pieces that exist only in the Burmese variant. They are written here in
# English so the translator has a source, and so an English-reading reviewer can
# check the Burmese against something. Both are rendered bilingually on the
# Burmese page: a governing-language clause that only appears in the translation
# is worth very little.
# --------------------------------------------------------------------------
NEW_BLOCKS = [
    ("notice.governing", "prose", "notice", [
        "This Burmese text is a translation provided for convenience.",
        "The English version of this letter is the governing text.",
        "If the Burmese and the English differ, the English version controls.",
    ]),
    ("notice.scope", "prose", "notice", [
        "What follows is United States federal tax law.",
        "It changes what a person owes only if that person files a United States federal income tax return.",
        "Most readers in Myanmar do not file one, and for them a gift to Win’s VPN Inc. reduces no tax at all.",
        "The English version of this letter does not say so; it was written for readers who file in the United States.",
        "A gift is still a gift; it is simply not a deduction outside the United States tax system.",
    ]),
]

# --------------------------------------------------------------------------
# Per-segment translator notes, keyed by a substring of the English source.
# These are the legally loaded terms. The first four are the specific defects
# the machine-translation attempt produced; see TRANSLATOR-BRIEF.md.
# --------------------------------------------------------------------------
NOTES = [
    ("you want the work funded",
     "TRAP. 'the work' = the charity's programme activity, the thing the "
     "organization does. It must NOT become 'business', 'company', or 'trade'. "
     "A 501(c)(3) has no business to fund. A back-translation of the machine "
     "attempt returned 'businesses' here."),
    ("caveat that applies to most filers",
     "TRAP. 'filers' = people who file a United States federal tax return. NOT "
     "'informer', 'notifier', 'reporter', or 'one who informs'. The machine "
     "attempt returned 'informers/notifiers'. Same word in callout.head."),
    ("MOST FILERS GET NO ITEMIZED DEDUCTION",
     "'filers' = people who file a US federal tax return. See ttl.sub. Keep "
     "this line's force: it is the single most important sentence on the page "
     "and it must stay blunt."),
    ("worth nothing to you",
     "TRAP. 'worth nothing' is deliberate and absolute. Do NOT soften to 'is "
     "not valuable', 'may not be useful', or 'has little benefit'. The machine "
     "attempt softened it. The reader must understand the deduction is worth "
     "zero, not merely small."),
    ("English version is the governing text",
     "TRAP. This is a legal clause about which text controls in a dispute, not "
     "a remark about the English being meaningful. The machine attempt "
     "returned 'the original document in English has meaning', which is not "
     "the same statement. Use the standard Burmese contract formula for a "
     "controlling / prevailing language."),
    ("English version controls",
     "Legal clause. 'controls' = prevails, governs, takes precedence. Not "
     "'manages' or 'operates'."),
    ("It is not a credit",
     "'credit' here = tax credit, a subtraction from tax owed. Distinct from "
     "'deduction', a subtraction from taxable income. The whole letter turns "
     "on this distinction; use two clearly different Burmese terms and keep "
     "them consistent everywhere."),
    ("standard deduction",
     "Term of art. Use one Burmese rendering for 'standard deduction' "
     "throughout and never reuse it for 'itemized deduction'."),
    ("itemize",
     "Term of art: to list deductions individually instead of taking the "
     "standard deduction. Keep 'itemize' / 'itemized deduction' distinct from "
     "'standard deduction' in every occurrence."),
    ("adjusted gross income",
     "Term of art (AGI). Use one rendering throughout. Where the source says "
     "'AGI' in a table cell, keeping the Latin abbreviation AGI is acceptable "
     "and preferred over an invented Burmese acronym."),
    ("carries over to the next 5 tax years",
     "Carryforward. The unused amount is not lost; it moves to later years. "
     "Keep the figure 5 as a Western Arabic digit."),
    ("written acknowledgment",
     "Term of art: the receipt the charity must issue. Not 'confirmation', "
     "'thanks', or 'agreement'. Same rendering in ack.lead and ack.body."),
    ("contemporaneous",
     "Legal term: obtained in time, before the filing deadline described in "
     "the same sentence. Do not drop it and do not translate it as 'modern'."),
    ("marginal tax rate",
     "The rate applying to the top dollar of income, not the average rate. Do "
     "not simplify to 'tax rate'."),
    ("public charity",
     "IRS classification, paired with 'private foundation' later. Keep the two "
     "distinct."),
    ("general information, not advice about your return",
     "Disclaimer. Must stay a clear denial that this is tax advice."),
    ("not a prediction",
     "Keep the denial explicit. This protects the organization."),
    ("does not follow the federal rules",
     "State and local rules differ from federal rules. Do not merge the two "
     "levels of government into one word."),
    ("tax-exempt status is a determination about the organization",
     "This sentence denies any government endorsement of the VPN product. "
     "Keep the denial intact; it is the honest framing the letter exists for."),
    ("recently approved organizations can take time to appear",
     "Explains why a lookup may find nothing. Keep it, or a reader who fails "
     "to find the listing will conclude the charity is fake."),
    ("planned only", "The recognition tiers do not exist yet. Keep the denial."),
    ("does not earn one", "Keep the denial: a gift now earns no badge."),
    ("about $", "Only the word 'about' is translated. The figure after it must "
                "stay exactly as printed, in Western Arabic digits."),
    ("non-itemizer cap", "The $1,000 / $2,000 ceiling for people who take the "
                         "standard deduction."),
    ("AGI floor removes", "The 0.5% floor. 'removes' = this much of the gift "
                          "stops being deductible."),
]

VERBATIM_NOTE = ("DO NOT TRANSLATE. Reproduce exactly as printed, in Latin "
                 "script. This is a legal name or a domain.")
FIGURE_NOTE = ("DO NOT TRANSLATE. Reproduce the figure exactly, in Western "
               "Arabic digits (0-9). No Burmese numerals.")

# Dotted tokens whose periods never end a sentence.
HARD_TOKENS = [
    "apps.irs.gov/app/eos", "support@winsvpn.org", "winsvpn.org", "irs.gov",
    "Rev. Proc.", "e.g.", "i.e.", "U.S.",
]
# Abbreviations whose period ends a sentence only when a capital follows.
SOFT_ABBREV = ["Inc.", "no.", "No.", "Sec.", "Pub.", "Rev.", "Proc."]


def split_sentences(text: str) -> list[str]:
    """Sentence split that survives '$1,000.', 'Inc.,', 'Rev. Proc. 2025-32'.

    'Inc.' is treated as a sentence end only where a capital letter follows,
    which is exactly the one place in this letter where it is one ('a gift to
    Win's VPN Inc. Before you give'). Colons and semicolons never split: the
    letter uses both mid-sentence.
    """
    holder = {}
    work = text

    def stash(tok: str) -> str:
        key = "\x00%d\x00" % len(holder)
        holder[key] = tok
        return key

    for tok in sorted(HARD_TOKENS, key=len, reverse=True):
        while tok in work:
            work = work.replace(tok, stash(tok), 1)
    for tok in sorted(SOFT_ABBREV, key=len, reverse=True):
        work = re.sub(re.escape(tok) + r'(?!\s+["“(A-Z])',
                      lambda m: stash(m.group(0)), work)
    # Decimals and version numbers: 0.5%, 509(a)(2), 2025-32
    work = re.sub(r"(\d)\.(\d)", lambda m: m.group(1) + "\x01" + m.group(2),
                  work)

    parts = re.split(r"(?<=[.?!])\s+(?=[A-Z(“\"\x00])", work)
    out = []
    for p in parts:
        p = p.replace("\x01", ".")
        for key, tok in holder.items():
            p = p.replace(key, tok)
        p = p.strip()
        if p:
            out.append(p)
    return out


def note_for(src: str, kind: str) -> str:
    if kind == "verbatim":
        return VERBATIM_NOTE
    if kind == "figure":
        return FIGURE_NOTE
    low = src.lower()
    hits = [n for key, n in NOTES if key.lower() in low]
    return "  ".join(hits)


# A figure is an optional '$', a digit run that may carry thousands commas and a
# decimal part, and an optional trailing '%'. Written so that a comma that ends a
# list item ("Silver $1,000, Gold") is never swallowed into the figure.
FIGURE_RE = re.compile(r"\$?\d{1,3}(?:,\d{3})+(?:\.\d+)?%?|\$?\d+(?:\.\d+)?%?")


def figures_in(s: str) -> list[str]:
    return FIGURE_RE.findall(s)


def main() -> int:
    root = ET.parse(SVG).getroot()
    lines = ["".join(e.itertext()) for e in root.iter(NS + "text")]
    if len(lines) != 92:
        sys.exit("expected 92 <text> elements in the SVG, found %d. The letter "
                 "changed; re-check the block map before trusting this run."
                 % len(lines))

    covered = sorted(i for _, _, idx, _, _ in BLOCKS for i in idx)
    if covered != list(range(92)):
        missing = sorted(set(range(92)) - set(covered))
        dupes = sorted({i for i in covered if covered.count(i) > 1})
        sys.exit("block map does not cover the SVG exactly. missing=%s dupes=%s"
                 % (missing, dupes))

    segments = []
    blocks_out = []
    seg_no = 0

    for bid, kind, idx, join, region in BLOCKS:
        sep = " " if join == "space" else ""
        source = sep.join(lines[i] for i in idx).strip()
        source = re.sub(r"\s+", " ", source)
        if kind == "prose":
            pieces = split_sentences(source)
            rejoined = " ".join(pieces)
            if re.sub(r"\s+", "", rejoined) != re.sub(r"\s+", "", source):
                sys.exit("round-trip failed for block %s\n  src: %r\n  out: %r"
                         % (bid, source, rejoined))
        else:
            pieces = [source]
        blocks_out.append({
            "id": bid, "kind": kind, "region": region,
            "svg_line_indices": idx, "source": source,
            "segment_ids": [],
        })
        for k, piece in enumerate(pieces, 1):
            seg_no += 1
            sid = "%03d" % seg_no
            blocks_out[-1]["segment_ids"].append(sid)
            segments.append({
                "id": sid, "block": bid, "kind": kind, "region": region,
                "order_in_block": k, "of_in_block": len(pieces),
                "source_en": piece, "target_my": "",
                "figures": figures_in(piece),
                "note": note_for(piece, kind),
            })

    for bid, kind, region, pieces in NEW_BLOCKS:
        blocks_out.append({
            "id": bid, "kind": kind, "region": region, "svg_line_indices": [],
            "source": " ".join(pieces), "segment_ids": [],
            "new_in_burmese": True,
        })
        for k, piece in enumerate(pieces, 1):
            seg_no += 1
            sid = "%03d" % seg_no
            blocks_out[-1]["segment_ids"].append(sid)
            segments.append({
                "id": sid, "block": bid, "kind": kind, "region": region,
                "order_in_block": k, "of_in_block": len(pieces),
                "source_en": piece, "target_my": "",
                "figures": figures_in(piece),
                "note": note_for(piece, kind),
                "new_in_burmese": True,
            })

    package = {
        "document": "donor-tax-deduction-letter",
        "source_svg": str(SVG.relative_to(REPO)),
        "source_language": "en",
        "target_language": "my",
        "tax_year": "2026",
        "svg_text_elements": len(lines),
        "logical_blocks": len(blocks_out),
        "segments": len(segments),
        "translatable_segments": sum(
            1 for s in segments if s["kind"] not in ("verbatim", "figure")),
        "verbatim_segments": sum(
            1 for s in segments if s["kind"] in ("verbatim", "figure")),
        "blocks": blocks_out,
        "segment_list": segments,
    }

    (HERE / "donor-letter.segments.json").write_text(
        json.dumps(package, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8")

    # CSV: the file the translator actually types into.
    with (HERE / "donor-letter.my.csv").open("w", newline="",
                                             encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "block", "kind", "english_source",
                    "burmese_translation", "figures_that_must_survive",
                    "translator_note"])
        for s in segments:
            w.writerow([s["id"], s["block"], s["kind"], s["source_en"],
                        s["source_en"] if s["kind"] in ("verbatim", "figure")
                        else "",
                        " ".join(s["figures"]), s["note"]])

    # Markdown worksheet: same content, readable, notes in full.
    md = ["# Donor tax letter: Burmese (my) segmentation worksheet", "",
          "Generated by `extract_segments.py` from `%s`."
          % SVG.relative_to(REPO), "",
          "* %d rendered `<text>` lines in the SVG" % len(lines),
          "* %d logical blocks" % len(blocks_out),
          "* %d segments, of which %d need translation and %d are reproduced "
          "verbatim" % (len(segments), package["translatable_segments"],
                        package["verbatim_segments"]), "",
          "Type your Burmese into `donor-letter.my.csv`, column "
          "`burmese_translation`. This Markdown file is for reading the notes; "
          "the CSV is the file that gets checked and built.", "",
          "Read `TRANSLATOR-BRIEF.md` first.", ""]
    last_block = None
    for s in segments:
        if s["block"] != last_block:
            last_block = s["block"]
            md.append("")
            md.append("## %s" % s["block"])
            md.append("")
        md.append("**%s** (%s)" % (s["id"], s["kind"]))
        md.append("")
        md.append("> %s" % s["source_en"])
        md.append("")
        if s["figures"]:
            md.append("Figures that must survive: `%s`"
                      % "`, `".join(s["figures"]))
            md.append("")
        if s["note"]:
            md.append("NOTE: %s" % s["note"])
            md.append("")
        md.append("Burmese: ")
        md.append("")
    (HERE / "donor-letter.segments.md").write_text("\n".join(md) + "\n",
                                                   encoding="utf-8")

    print("svg <text> lines      : %d" % len(lines))
    print("logical blocks        : %d" % len(blocks_out))
    print("segments total        : %d" % len(segments))
    print("  need translation    : %d" % package["translatable_segments"])
    print("  verbatim / figures  : %d" % package["verbatim_segments"])
    print("wrote donor-letter.segments.json, donor-letter.my.csv, "
          "donor-letter.segments.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
