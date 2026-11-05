# Digit-verification checklist: Burmese donor tax letter

Every figure in this letter is quoted, not computed by us at translation time. A
reader may need to match it against an English IRS form or an IRS web page. So
each one has to come out of translation **identical, in Western Arabic digits**.

Two things are checked here and they are different:

* **Survival.** The figure still appears, in the right block, in Latin digits.
  This is mechanical and `check_translation.py` does all of it.
* **Correctness.** The figure is the right figure for tax year 2026. This is
  *not* re-checked at translation time. The figures were fixed when the English
  letter was written and **must not change in either language**. If a figure is
  wrong, that is an English-edition problem and both editions get corrected
  together, before translation.

---

## 1. The figures the owner signed off on

These are the ones the automated checker demands by name. Each is checked inside
a named block, not merely somewhere on the page, so that finding a stray `5`
elsewhere cannot make the check pass.

| # | Figure | Meaning | Must appear in block |
| --- | --- | --- | --- |
| 1 | `60%` | ceiling on the deduction for cash gifts, as a share of AGI | `ceil.body` |
| 2 | `5` | tax years an excess contribution carries forward | `ceil.body` |
| 3 | `$1,000` | non-itemizer cash deduction, single, new for 2026 | `callout.body` |
| 4 | `$2,000` | non-itemizer cash deduction, joint return, new for 2026 | `callout.body` |
| 5 | `0.5%` | AGI floor on itemized giving, new for 2026 | `arith.body` |
| 6 | `$16,100` | 2026 standard deduction, single filer | `callout.body` |
| 7 | `$32,200` | 2026 standard deduction, married filing jointly | `callout.body` |
| 8 | `$24,150` | 2026 standard deduction, head of household | `callout.body` |
| 9 | `$250` | threshold above which a written acknowledgment is required | `ack.body` |
| 10 | `2026` | the tax year, in the caveat box | `callout.body` |
| 11 | `2026` | the tax year, in the letterhead pill | `hdr.taxyear` |
| 12 | `2026` | the tax year, in the subtitle | `ttl.sub` |
| 13 | `50%` | ceiling applying to other kinds of gift | `ceil.body` |
| 14 | `$100,000` | the largest illustrated gift | anywhere |

Sources, as stated by the letter itself in its own fine print: IRS Publications
526 and 1771, IRS Topic no. 506, and Rev. Proc. 2025-32. The letter also states
that dollar figures are for the 2026 tax year and change annually. Those source
citations are part of the text and are themselves translated content that must
survive: `526`, `1771`, `506`, `2025-32`.

---

## 2. The full inventory

The checker additionally verifies, block by block, that **every** figure present
in the English block is present in the corresponding Burmese block, with at
least the same multiplicity. That is 89 figure occurrences across 40 blocks.

| Block | Figures |
| --- | --- |
| `hdr.status` | 501, 3, 509, 2 |
| `hdr.exempt` | 11, 2026 |
| `hdr.taxyear` | 2026 |
| `ttl.sub` | 2026 |
| `body.p2` | 2026 |
| `callout.body` | $16,100, $32,200, $24,150, $1,000, $2,000, 2026 (x2) |
| `arith.body` | 0.5%, $1,000 (x3), $2,000, 2026 |
| `row1.*` | $100, $60,000, $100, $1,000, 12%, $12, $88 |
| `row2.*` | $1,000, $95,000, $1,000, 22%, $220, $780 |
| `row3.*` | $10,000, $300,000, $8,500, 0.5%, $1,500, 24%, $2,040, $7,960 |
| `row4.*` | $100,000, $600,000, $97,000, 0.5%, $3,000, 35%, $33,950, $66,050 |
| `tbl.footnote` | $100, $1,000, $10,000, $100,000 |
| `ceil.body` | 60%, 50%, 30%, 20%, 5, 526 |
| `ack.lead` | $250 |
| `ack.body` | $250 (x2), 1771 |
| `sign.orgsuffix` | 501, 3 |
| `fine.print` | 501, 3, 21, 2026 (x4), 11, 509, 2, 31, 990, 170, 2055, 2106, 2522, 506, 526, 1771, 2025, 32 |

The `row*.gift`, `row*.deduct` and `row*.rate` cells are `figure` rows in the
CSV: they are pre-filled and must be returned byte for byte.

---

## 3. Character-level rules

| Rule | Why | Checked by |
| --- | --- | --- |
| No Myanmar digits ၀ ၁ ၂ ၃ ၄ ၅ ၆ ၇ ၈ ၉ (U+1040 to U+1049) | breaks matching against IRS documents; leaked once already | codepoint scan |
| No Shan digits (U+1090 to U+1099) | same | codepoint scan |
| No non-ASCII decimal digit of any script | catches Arabic-Indic, Devanagari and the rest | Unicode category `Nd` scan |
| Thousands separator stays `,` | `$16,100` not `$16.100` and not `$16 100` | exact figure match |
| Decimal point stays `.` | `0.5%` | exact figure match |
| `$` stays `$` | count per block must not fall | symbol count |
| `%` stays `%` | count per block must not fall | symbol count |
| No em dash, en dash, horizontal bar, figure dash or minus sign | house rule | codepoint scan |
| No `NN-NNNNNNN` EIN pattern | no EIN on any public web surface | regex |
| No street address pattern | no address on any public web surface | regex |

---

## 4. Running it

```
cd brand/donor_recognition/i18n/my
python3 check_translation.py donor-letter.my.csv
```

Exit status 0 and `0 FAIL` is the only acceptable result. While translation is
still in progress, add `--allow-incomplete` to downgrade the empty-target
failure to a warning and leave every other check active.

The checker was verified against six deliberately corrupted copies of a test
file. Each was caught:

| Injected defect | Reported as |
| --- | --- |
| Latin digits converted to Myanmar digits in one segment | `NUMERALS` plus 3 `REQUIRED FIGURE` plus `FIGURES` block loss |
| `60%` deleted from `ceil.body` | `REQUIRED FIGURE` plus `FIGURES` plus `SYMBOLS` |
| Em dash and en dash appended to a segment | `DASHES`, with codepoint and name |
| A segment left in English | `UNTRANSLATED` |
| An EIN appended to the fine print | `DISCLOSURE` |
| The `winsvpn.org` verbatim row translated | `VERBATIM`, with expected and actual |

All six exited 1. A clean file exited 0.

**A clean run does not mean the translation is right.** It means nothing
mechanical is wrong with it. Meaning is checked by the human back-translation
step in `TRANSLATOR-BRIEF.md` section 7.
