# Publishing the Burmese donor letter

Everything below waits on one thing: a **human** Burmese translation in
`donor-letter.my.csv`. Until that exists, the site shows the Burmese slot as
empty and says why. Do not shortcut this with a machine translation.

Nothing here deploys. The owner deploys.

---

## What is already built and live in the repository

`web/index.html` already carries the language selector, the switching script,
the empty Burmese slot and the governing-language notice. That work is done. The
only thing missing is the translation itself and the two rendered images.

| Piece | State |
| --- | --- |
| `Letter language` dropdown in the donations card | built, English selected |
| `English` option | working |
| Burmese option, labelled `မြန်မာ (Burmese): not yet available` | present, `disabled` |
| Burmese version container `[data-letter-lang="my"]` | present, `hidden`, no image |
| Governing-language notice as page text | present inside the Burmese container, shown only when a non-English version is selected |
| Fallback with scripting unavailable | English container is not `hidden` in the markup, so it renders |
| Fallback on an unknown language value | script resets the dropdown to `en` |

---

## Step 1: get the translation and check it

```
cd brand/donor_recognition/i18n/my
python3 check_translation.py donor-letter.my.csv
```

Must print `0 FAIL`. See `DIGIT-CHECKLIST.md` for what it checks and
`TRANSLATOR-BRIEF.md` section 7 for the human back-translation step that the
script cannot do.

## Step 2: build the images

```
python3 build_my_svg.py --translation donor-letter.my.csv --final
```

This writes:

* `brand/donor_recognition/donor-tax-deduction-letter-my.svg`
* `web/assets/donor-tax-deduction-letter-my.webp` at 1200x1553
* `web/assets/donor-tax-deduction-letter-my-thumb.webp` at 420x544

matching the English pair. Drop `--final` to write the images into `proof/`
instead while you are still iterating.

The builder refuses to emit anything it cannot fit on one page. If it stops with
a message about content being too tall, read it: the two notices this edition
adds are the only text that is ours to shorten.

## Step 3: look at the rendered image

Open `web/assets/donor-tax-deduction-letter-my.webp` and read it. Check the
figures against `DIGIT-CHECKLIST.md` section 1 by eye as well, because a figure
can survive the checker and still land in the wrong sentence.

## Step 4: three edits to `web/index.html`

All three are inside the donations `<article class="legal-card">`, in the block
that begins `<div class="letter-lang"`.

**4a.** Remove `disabled` from the Burmese option:

```html
<option value="my" lang="my">မြန်မာ</option>
```

Drop the `: not yet available` wording at the same time. The option label stays
in Burmese, which is the convention readers scan for.

**4b.** Inside `<div class="letter-version" data-letter-lang="my" hidden>`,
replace the `<p class="letter-pending">...</p>` paragraph with the same
thumbnail-link and caption shape the English block uses:

```html
            <p><a href="assets/donor-tax-deduction-letter-my.webp" target="_blank" rel="noopener noreferrer"><img src="assets/donor-tax-deduction-letter-my-thumb.webp" loading="lazy" decoding="async" alt="Burmese edition of the one-page Win's VPN Inc. donor letter, explaining that a charitable deduction reduces taxable income rather than tax owed, that most filers get no itemized deduction, and showing four illustrative gift examples for the 2026 tax year, with an added notice that these are United States federal rules which change what a person owes only if that person files a United States federal return"></a></p>
            <p>One-page donor letter on Win's VPN Inc. letterhead, written for the 2026 tax year, in Burmese. <a href="assets/donor-tax-deduction-letter-my.webp" target="_blank" rel="noopener noreferrer">Open the full-size Burmese letter.</a> It was translated by a person. This is a document we wrote ourselves, not a government record like the documents in <a href="#proof">Proof</a>, and it is general information about the law rather than tax advice.</p>
```

Keep the `hidden` attribute on the container. The script removes it when Burmese
is selected, and leaving it there is what keeps English showing when scripting
is unavailable.

**4c.** Add the Burmese rendering of the governing-language notice directly
under the English one, using segments 093 to 095 from
`donor-letter.segments.json`:

```html
            <p class="letter-governing" lang="my" translate="no">[segments 093, 094 and 095 in Burmese]</p>
```

Keep `translate="no"` on both. It stops the site's runtime translation API
rewriting a clause whose whole job is to say which text controls.

## Step 5: resync the CSP and check the page

```
python3 web/update_style_csp.py
```

It must end with `in sync` (or `nothing to change` if the inline `<style>` and
`<script>` were untouched, which means the same thing). It exits non-zero and
prints `FAILED` if a hash ends up in the wrong directive.

Then open the page and check at **375**, **768** and **1280** pixels. At 1280
the donations column is about 536px wide, which is what the thumbnail and the
dropdown are sized against. Verified values with the selector in place:

| Viewport | Donations column | Thumbnail | Horizontal overflow |
| --- | --- | --- | --- |
| 375px | 351px | 305x395 | none |
| 768px | 740px | 420x544 | none |
| 1280px | 536px | 420x544 | none |

Also confirm:

* tabbing reaches the dropdown and shows a visible focus ring,
* choosing Burmese swaps the image **and** shows the governing-language notice,
* choosing English swaps back,
* with JavaScript disabled the English letter still renders.

## Step 6: remove the layout-proof files

The proof render is deliberately named so it cannot be mistaken for the real
thing, and it carries a `PLACEHOLDER / LAYOUT PROOF ONLY / TEXT IS NOT A
TRANSLATION` watermark. It still must not ship:

```
rm web/assets/donor-tax-deduction-letter-my.PLACEHOLDER.webp
rm web/assets/donor-tax-deduction-letter-my-thumb.PLACEHOLDER.webp
```

Nothing references them, but they sit in the deploy directory.

---

## Adding a third language later

The structure takes more languages without further design work:

1. Add an `<option value="XX" lang="XX">` labelled in its own language.
2. Add a `<div class="letter-version" data-letter-lang="XX" hidden>` containing
   the governing-language notice and the image.
3. Regenerate the segment package, translate, check, build with
   `build_my_svg.py` adapted for the new locale.

The switching script is generic: it matches the dropdown value against
`data-letter-lang` and falls back to `en` for anything it cannot show.
