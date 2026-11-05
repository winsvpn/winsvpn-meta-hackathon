# Burmese (`my`) edition of the donor tax letter

Everything needed to get a trustworthy human Burmese translation of
`brand/donor_recognition/donor-tax-deduction-letter.svg` onto winsvpn.org, and
nothing that would let a machine translation get there by accident.

## Why this directory exists

An earlier attempt translated the letter with local models and checked the
result by blind back-translation, twice, with a control sentence proving the
checker was reading. Roughly five of the first twenty-four segments came back
meaning something different from the English, concentrated on the lines that
matter most: "the work" became "businesses", "filers" became
"informers/notifiers", the governing-language clause lost its legal meaning,
"worth nothing" was softened, and Burmese numerals leaked into a figure. That
attempt correctly stopped before publishing.

So the job here is not to translate. It is to make a human translator's work
fast, cheap and verifiable, and to have the rendering and publishing path
finished and proven so that when the translation arrives the only remaining step
is substituting strings.

## Files

| File | What it is |
| --- | --- |
| `TRANSLATOR-BRIEF.md` | **Read first.** The specific traps, the terms of art, how the file works |
| `donor-letter.my.csv` | The file the translator types into |
| `donor-letter.segments.md` | The same content laid out for reading, notes in full |
| `donor-letter.segments.json` | Canonical machine-readable package, consumed by the checker and the builder |
| `DIGIT-CHECKLIST.md` | Every figure that must survive, and the character-level rules |
| `PUBLISH-BURMESE.md` | The publishing procedure, once a translation exists |
| `extract_segments.py` | Regenerates the three segment files from the source SVG |
| `check_translation.py` | Mechanical verification of a completed translation |
| `build_my_svg.py` | Builds the Burmese SVG and renders the WebP pair |
| `proof/` | The layout proof: filler Burmese, watermarked, never publishable |

## The numbers

* 92 rendered `<text>` lines in the source SVG
* 64 logical blocks
* 102 segments, of which **87 need translation** and 15 are reproduced verbatim
* 89 figure occurrences across 40 blocks, all of which the checker verifies

A rendered line is not a unit of meaning here: single sentences are split across
four of them. `extract_segments.py` regroups the lines into blocks, splits each
prose block into sentences, and asserts that re-joining a block's segments
reproduces its source text exactly, so no wording can be dropped in the process.

## Commands

```
python3 extract_segments.py                              # regenerate the package
python3 check_translation.py donor-letter.my.csv         # verify a translation
python3 build_my_svg.py --placeholder                    # layout proof, filler text
python3 build_my_svg.py --translation donor-letter.my.csv --final   # the real thing
```

No model is loaded by anything in this directory and none is needed. The only
external process is headless Chrome, used for text measurement and for the
screenshot.

## Why Chrome

Burmese is written without spaces between words, so wrapping on `" "` produces
either one enormous line or breaks in the middle of a word. Chrome carries ICU,
which knows where Burmese words end. `build_my_svg.py` lays every block out in a
headless Chrome page at the exact font, size and column width the SVG will use,
reads the real line boxes back, and emits one `<text>` element per line at the
position Chrome chose.

Leading is measured, not guessed. Canvas `TextMetrics` on this machine gives a
Burmese line an ink height of 1.47 em for ordinary prose and 1.56 em for a worst
case mixing deep below-marks with tall stacks, against 1.01 em for Latin. The
builder is allowed to compress leading between those two values and no further.

## What the proof shows

`proof/donor-tax-deduction-letter-my.PLACEHOLDER.png` is a full render of the
Burmese page using generated Burmese filler of the same measured width as the
English source, with every real figure embedded in Western Arabic digits. It
carries a `PLACEHOLDER / LAYOUT PROOF ONLY / TEXT IS NOT A TRANSLATION`
watermark. The filler is concatenated whole Burmese syllable clusters: valid
script, obvious nonsense, impossible to mistake for a translation.

It proves the page fits, the fonts resolve with no tofu, the ICU line breaking
works, the figures survive, and the WebP pair comes out at the right sizes.
