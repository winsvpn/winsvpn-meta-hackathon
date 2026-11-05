# Win's VPN Inc. — Donor Recognition Artwork

Four tier badges and one certificate of recognition. Everything here is
self-contained SVG: no webfonts, no remote images, no `<image>`, no `<script>`,
no `@import`. Every `url(...)` reference is an internal `#fragment`. The files
render identically offline, behind a strict CSP, and in print pipelines.

| File | What it is |
| --- | --- |
| `badge-diamond.svg` | Diamond tier — contributions of $100,000 or more |
| `badge-gold.svg` | Gold tier — $10,000 or more |
| `badge-silver.svg` | Silver tier — $1,000 or more |
| `badge-bronze.svg` | Bronze tier — $100 or more |
| `certificate-of-recognition.svg` | Certificate + IRS-compliant written acknowledgment |
| `donor-tax-deduction-letter.svg` | One-page donor letter, US Letter **portrait**, explaining what a charitable deduction is worth. No placeholders — it ships filled. Rendered to `web/assets/donor-tax-deduction-letter{,-thumb}.webp` and published in the site's `#donations` section. Carries no EIN by owner decision (2026-08-03) |
| `sample-filled-certificate.svg` / `.pdf` | A real certificate produced end to end by the control-plane engine (§8), for review. Zero unreplaced tokens |
| `preview.html` | Combined review page. Open it in any browser; no server needed |

---

## 1. Placeholder substitution

Every fillable field is a `{{TOKEN}}`. Substitution is a plain find-and-replace
on the file text — no XML parsing required.

### Badges

| Token | Example | Notes |
| --- | --- | --- |
| `{{TAX_YEAR}}` | `2026` | 3 occurrences per badge — the visible pill plus the `<title>` and `aria-label`. Replace all of them. The pill is sized for four digits. |

Each badge is valid for one tax year, so issue a fresh file per year rather than
editing one in place.

### Certificate

| Token | Example | Notes |
| --- | --- | --- |
| `{{DONOR_NAME}}` | `Alexandra M. Whitfield` | 36 px Georgia. Fits ~30 characters. See §4 for longer names. |
| `{{AMOUNT}}` | `$25,000.00 (twenty-five thousand USD)` | The **cash** amount. Required element. ~44 characters at 12 px. |
| `{{CONTRIBUTION_DATES}}` | `March 4, 2026 and September 19, 2026` | See §3 on annual summaries. ~44 characters at 12 px. |
| `{{NONCASH_DESCRIPTION}}` | `None` | Description only — never a value. See §2. |
| `{{GOODS_VALUE}}` | `$0.00 — none provided` | Good-faith estimate of goods/services value. |
| `{{GS_LINE_1..3}}` | see §2 | The goods-and-services statement, one token per line. |
| `{{TIER}}` | `GOLD` | Appears twice (title block and issuance panel). |
| `{{TAX_YEAR}}` | `2026` | Appears twice (letterhead pill and issuance panel). |
| `{{EIN}}` | `42-3223917` | Appears three times (letterhead, panel, fine print). |
| `{{ACK_NUMBER}}` | `WV-2026-000418` | Your internal acknowledgment reference. |
| `{{DATE_ISSUED}}` | `January 14, 2027` | The date you issue the acknowledgment. |
| `{{SIGNATORY_NAME}}` | | Printed under the signature rule. |
| `{{SIGNATORY_TITLE}}` | `President, Win's VPN Inc.` | |
| `{{ORG_CONTACT}}` | `winsvpn.org` | Centred footer line. **Left as a placeholder on purpose** — see §6. |

SVG text does not wrap. Anything that overflows its column will simply run past
it, so respect the character budgets above, or drop the font size for that one
`<text>` element.

**If you are filling this by hand you must respect those budgets yourself.** The
automated path does not: the engine in the control plane measures every field
against its column, shrinks the font for that one element if needed, wraps the
goods-and-services statement across the three lines available to it, and refuses
to emit a certificate it cannot fit. See §8.

**Type sizes were raised on 2026-08-03** so that the elements IRS Publication
1771 actually requires are ordinary reading size rather than fine print — the
panel values and the goods-and-services statement went from 10 px and 9.5 px to
12 px (9 pt at print size), and the statement lines were re-spaced from a 13 px
to a 15 px pitch. Pub. 1771 warns that small print may not qualify, so the
required content leads and the layout follows. The row labels stayed at 7.5 px:
`GOOD-FAITH VALUE OF GOODS/SERVICES` already runs to x≈257 against a value
column that starts at x=262, and enlarging the labels would collide with it.

---

## 2. The goods-and-services statement — do not skip this

This is the element most often missed, and the one that makes an otherwise
beautiful certificate worthless to the donor at filing time.

> **Never issue a certificate with `{{GS_LINE_1}}` still showing.** The sentence
> is deliberately *not* pre-filled: a template that shipped with "no goods or
> services were provided" baked in would silently print a false statement on the
> day a tier does carry a benefit. An unreplaced token fails loudly instead,
> which is the safer failure. Substituting it is a required step, not an
> optional one.

Replace `{{GS_LINE_1}}`, `{{GS_LINE_2}}` and `{{GS_LINE_3}}` with **one** of the
following. Unused lines get an empty string. Roughly **70 characters per line**
at the 12 px the statement is now set in (it was ~90 at 9.5 px), so the normal
sentence takes two lines rather than one. The engine wraps this for you.

**Normal case — nothing was given in return:**

```
GS_LINE_1: No goods or services were provided by Win's VPN Inc. in return for this
GS_LINE_2: contribution.
GS_LINE_3: (empty)
GOODS_VALUE: $0.00 - none provided
```

**Exception — something of real value was given in return:**

```
GS_LINE_1: In return for this contribution, Win's VPN Inc. provided [description], with a
GS_LINE_2: good-faith estimate of fair market value of $[amount]. The amount deductible for federal income tax
GS_LINE_3: purposes is limited to the excess of the amount contributed over the value of what was received.
GOODS_VALUE: $[amount]
```

Two rules that go with it:

- **Non-cash gifts are described, never valued.** The certificate prints this
  reminder under the field. Valuing donated property is the donor's job, not the
  organization's.
- **A recognition tier must never carry a benefit with a market price** — no VPN
  plan, no extra devices, no priority support, no merchandise. If it does, the
  "no goods or services" sentence becomes false for every donor at that tier,
  each gift becomes a quid pro quo contribution, and the separate >$75 written
  disclosure rule is triggered. Badges and certificates are *recognition*: write
  "in recognition of", never "in exchange for", "for", or "unlocks".

---

## 3. Using the certificate as an annual summary

One acknowledgment may cover several gifts, but it must still let the donor
identify **each single gift of $250 or more** individually. Either list them in
`{{CONTRIBUTION_DATES}}`, or set that field to
`Various dates in 2026 (see attached schedule)` and attach a schedule listing
each gift's date and amount.

Separate gifts of under $250 are never aggregated into one $250 gift. A
recurring $50/month donor has twelve sub-$250 gifts, and an annual summary
cannot change that.

---

## 4. Print notes

- The certificate declares `width="11in" height="8.5in"` with
  `viewBox="0 0 1056 816"`, so it prints at exact US Letter landscape size.
- **Print at 100% — do not select "fit to page" or "shrink to fit."** Scaling
  moves the borders relative to the sheet.
- Borders sit 0.29 in from the trim edge, inside the ~0.25 in non-printable
  margin of typical desktop printers. No bleed is required.
- The page is white with a very light tint that stops at the inner border, so
  the outer margin stays pure white. The only ink-heavy element is the navy
  letterhead band.
- To produce a PDF: open the SVG in a browser and print to PDF (landscape,
  100%, background graphics on), or run
  `rsvg-convert -f pdf -o cert.pdf certificate-of-recognition.svg`.
- **Long donor names:** above ~30 characters, reduce the `font-size="36"` on the
  `{{DONOR_NAME}}` text element to `30` or `26`. It is the only element likely
  to need it. The engine does this automatically, in 0.5 px steps down to 18 px.
- Fine print is set at 8 px (≈6 pt at print size). It is legible but small; the
  substantive acknowledgment elements are all in the panels at **12 px (9 pt at
  print size)**, not in the fine print, precisely so nothing required is buried.
  Nothing the IRS requires lives in the fine print: the organization name, the
  amount, the date(s), the non-cash description and the goods-or-services
  statement are all panel content.

---

## 5. Badge usage

- **Design target is 100×100 px.** Verified legible there and at 64 px, on both
  white and dark backgrounds. Do not issue below 64 px.
- Square canvas, `viewBox="0 0 512 512"`, rounded plate with transparent
  corners, so a badge composites cleanly on any background.
- The tiers are distinguished by silhouette first, metal second, and text last:
  bare shield (bronze), circular ring (silver), wings and star arc (gold),
  faceted octagon with sparkles (diamond). That ordering is deliberate — at
  100 px the silhouette is what a viewer actually resolves.
- The `WIN'S VPN` wordmark is drawn as outline paths, not type, so it is
  metrically identical in every renderer. Everything else uses a system font
  stack that matches the website.
- To raster: `rsvg-convert -w 400 -h 400 -o badge-gold.png badge-gold.svg`, or
  open `preview.html` and export.
- **No badge platform's marks, logos or names appear in any of these files.**
  Nothing here states or implies a partnership with any credential platform.

---

## 6. Deliberately left for the owner

1. **`{{ORG_CONTACT}}`** — set to `winsvpn.org`, an org email, or both. Not
   hard-coded because no donations-specific address is published, and the
   street address is deliberately absent everywhere in these files.
   *The engine defaults it to `winsvpn.org  |  <EMAIL_SENDER>`, which resolves
   to `winsvpn.org  |  support@winsvpn.org`. Override with
   `DONOR_ACK_ORG_CONTACT`. Never set it to the street address.*
2. **`{{SIGNATORY_NAME}}` / `{{SIGNATORY_TITLE}}`** — the authorised signer is
   an organizational decision, not a design one.
   *The engine leaves `{{SIGNATORY_NAME}}` empty until you set
   `DONOR_ACK_SIGNATORY_NAME`, so the rule prints clear to be signed by hand,
   and it prints the generic `Authorized Officer, Win's VPN Inc.` as the title.
   It invents no name and composites no signature image. Pub. 1771 does not
   list a signature among the required elements, so an unsigned acknowledgment
   is still valid at filing time — a fabricated one would not be.*
3. **`{{ACK_NUMBER}}` format** — `WV-2026-000418` is a suggestion, not a scheme.
   *The engine adopted it: `WV-<tax year>-<6 digits>`, allocated monotonically
   per tax year and protected by `UNIQUE (tax_year, sequence)`.*
4. **Tier thresholds are not printed on the badges or the certificate.** They
   live in this README and in `preview.html` only, so the thresholds can be
   changed without reissuing artwork.
5. **A CPA or nonprofit counsel should review the filled template before it goes
   out at volume.** This artwork carries the required elements; it is not tax
   advice and has not been reviewed by a tax professional.

---

## 7. IRS compliance basis

The certificate doubles as the **contemporaneous written acknowledgment** a
donor needs to deduct any single contribution of $250 or more
(IRC 170(f)(8); Reg. 1.170A-13(f)). Element list and wording follow **IRS
Publication 1771, *Charitable Contributions — Substantiation and Disclosure
Requirements* (Rev. 11-2023), page 3**
(<https://www.irs.gov/pub/irs-pdf/p1771.pdf>), cross-checked against
<https://www.irs.gov/charities-non-profits/charitable-organizations/charitable-contributions-written-acknowledgments>.
Fuller treatment, including the quid pro quo and token-benefit rules, is in
`../../DONOR_ACKNOWLEDGMENT_REQUIREMENTS.md`.

| Pub. 1771 required element | Where it lives on the certificate |
| --- | --- |
| 1. Name of the organization | Letterhead wordmark, and the `ORGANIZATION` row |
| 2. Amount of any monetary contribution | `AMOUNT OF CASH CONTRIBUTION` row |
| 3. Description (but not value) of any property | `NON-CASH CONTRIBUTION, IF ANY` row, with the "described, not valued" note |
| 4. Statement that no goods or services were provided, if so | Goods-or-services statement block |
| 5. Description + good-faith estimate of value, if any were provided | `GOOD-FAITH VALUE` row plus the statement block |
| 6. Intangible religious benefits statement, if applicable | **Omitted on purpose** — Win's VPN Inc. is not organized for religious purposes, so this element can never apply |

Also carried, though not on the statutory list: the **date(s) of contribution**,
which the separate recordkeeping rule for monetary gifts requires
(IRC 170(f)(17); Reg. 1.170A-15), and the EIN, which is optional but useful.
The donor's SSN or taxpayer ID is **not** required and must never be printed.

**Timing.** "Contemporaneous" means the donor must *receive* it on or before the
earlier of the date they file their return for the year of the contribution, or
that return's due date including extensions. Issue on receipt of payment, and
again as a January annual summary. Do not wait.

### Statements the artwork deliberately makes, and does not make

- States that exemption is **a determination about the organization, not an IRS
  review, approval or endorsement of the Win's VPN service**.
- States that deductibility **depends on the donor's own tax situation** and that
  Win's VPN Inc. does not give tax advice. No specific tax saving is stated or
  implied anywhere.
- States that the donor should **retain the acknowledgment and not attach it to
  the return**.
- Points the donor at `apps.irs.gov/app/eos` to **verify the status
  independently**.
- Carries **no street address**, no accreditation, no award, no endorsement, and
  no third-party marks.

---

## 8. The automation

The artwork is populated and delivered by an engine embedded in the control
plane, inside the `cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc of
`server/wins_control_plane_setup_ONETOUCH.sh`. The installer also writes a copy
of `certificate-of-recognition.svg` to `${APP_DIR}/assets/`, which is the file
the engine actually fills at run time.

| Function | What it does |
| --- | --- |
| `donor_certificate_fields(...)` | Derives all 16 tokens from donation data. The single source of truth for every output. |
| `donor_render_certificate_svg(fields)` | Fits, wraps, substitutes, then refuses to return a document containing `{{...}}`. |
| `donor_svg_to_pdf(svg)` | Converts the populated SVG. `rsvg-convert` first (`librsvg2-bin`, installed by the setup script), then `cairosvg`, then headless Chromium. |
| `donor_issue_and_deliver(...)` | Mints the acknowledgment number, renders, stores, and emails through the existing SMTP2GO path. |
| `donor_assert_no_unreplaced_tokens(svg)` | The hard guard. Runs at render time and again immediately before sending. |

Derivation rules, in one place:

| Field | Rule |
| --- | --- |
| `{{TIER}}` | From the amount recognised on the certificate: ≥100000 DIAMOND, ≥10000 GOLD, ≥1000 SILVER, ≥100 BRONZE. Below $100 there is no badge tier and it prints `SUPPORTER`. |
| `{{TAX_YEAR}}` | From the contribution date, never from today. One certificate covers one tax year; gifts spanning two are refused. |
| `{{CONTRIBUTION_DATES}}` | One date; two or three joined with "and"; four or more become `Various dates in YYYY (see attached schedule)` with a per-gift schedule attached. |
| `{{ACK_NUMBER}}` | `WV-<tax year>-<6 digits>`, monotonic per tax year. |
| `{{DATE_ISSUED}}` | The day of issue, not the day of the gift. |
| `{{AMOUNT}}` | Cash only, to exact cents, `ROUND_HALF_UP`. |
| `{{GS_LINE_1..3}}` | Always substituted explicitly. Never pre-filled in the template. |

**PDF is the primary format.** It is converted from the very same populated SVG
that is stored, so there is no separate "pretty" and "compliant" version to
drift apart. When a host has no converter the engine attaches the populated SVG
and records `svg_only:<reason>` rather than silently downgrading to an image.

`sample-filled-certificate.svg` and `sample-filled-certificate.pdf` in this
directory were produced end to end by that engine, from the real installer
source. They contain zero unreplaced tokens.
