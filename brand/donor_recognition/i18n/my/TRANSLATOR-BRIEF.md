# Brief for the Burmese translator: Win's VPN Inc. donor tax letter

You are translating a one-page letter that explains United States federal
charitable-deduction rules to people considering a gift to a US registered
501(c)(3) charity. It is published as an image on winsvpn.org.

Read this whole page before you start. It is short, and every item in it is
something that already went wrong once.

**Your working file is `donor-letter.my.csv`.** Type Burmese into the
`burmese_translation` column and change nothing else. `donor-letter.segments.md`
is the same content laid out for reading, with the notes in full.

---

## 1. What kind of document this is

It is not marketing. It is a plain-language legal explainer whose whole purpose
is to stop a donor from expecting a tax benefit they will not get. Its tone is
deliberately flat and slightly discouraging in places. **Keep it that way.** If
your Burmese reads warmer, more persuasive or more hopeful than the English,
that is a mistranslation, not an improvement.

Three things in it must survive intact, because they are the reason it exists:

1. the figures and the sources they come from,
2. the "READ THIS FIRST" caveat that most filers get no itemized deduction,
3. the honest framing: the letter repeatedly says what it cannot do and what a
   gift will not buy.

---

## 2. The specific traps

An earlier machine translation of this letter was checked by blind
back-translation, twice, with a control sentence proving the checker was
actually reading. Around five of the first twenty-four segments came back
meaning something different from the English. They are listed here so you do not
repeat them. These are the exact places to slow down.

### 2.1 "the work" is not "business"

> Please give because you want **the work** funded, not because you expect the
> government to hand the money back.

"the work" means **the charity's programme activity**, the thing the
organization actually does for people. The machine translation rendered it as
**"businesses"**, which is worse than clumsy: it describes a 501(c)(3) public
charity as a commercial operation, which is the one thing it legally is not.

Do not use a word meaning business, company, enterprise, trade or commerce.
Use a word meaning the charitable work, the activity, the mission.

### 2.2 "filers" means people who file a tax return

> the caveat that applies to most **filers**
> READ THIS FIRST: MOST **FILERS** GET NO ITEMIZED DEDUCTION

A "filer" is **a person who files a United States federal income tax return**.
The machine translation rendered it as **"informers" / "notifiers"**, as though
these were people who report something to the authorities. That is a different
and unpleasant meaning.

Use a phrase meaning "people who file a tax return" or "taxpayers who file a
return". Use the same phrase in both places.

### 2.3 The governing-language sentence is a legal clause

> The English version of this letter is **the governing text**.
> If the Burmese and the English differ, the English version **controls**.

This is the standard contract clause saying which language wins in a dispute. It
is not a comment about the English being meaningful. The machine translation
returned **"the original document in English has meaning"**, which says nothing
and protects nobody.

Use the ordinary Burmese legal formula for a controlling or prevailing language
version. "controls" here means prevails, governs, takes precedence. It does not
mean manages or operates.

### 2.4 "worth nothing" is deliberate and absolute

> an itemized charitable deduction is **worth nothing** to you

The machine translation softened this to **"is not valuable for you"**. That is
too gentle. The sentence means the deduction is worth **zero**: not small, not
limited, not of little use. Zero.

This is the most important sentence in the letter for the reader's own money.
Keep it blunt. If your Burmese would naturally hedge here, do not hedge.

### 2.5 Digits stay in Western Arabic form

Every number, currency amount and percentage must appear as **0 1 2 3 4 5 6 7 8
9**, never as ၀ ၁ ၂ ၃ ၄ ၅ ၆ ၇ ၈ ၉. The machine translation leaked Burmese
numerals into one segment despite being told not to.

The reason is not style. These figures are quoted from IRS publications and a
reader may need to match them against an English form or an IRS web page. A
converted numeral breaks that.

`check_translation.py` fails the file if a single Burmese digit appears
anywhere, so this one is caught automatically. See `DIGIT-CHECKLIST.md`.

---

## 3. Terms of art: pick one rendering and never vary it

The letter turns on distinctions that collapse if the vocabulary drifts. Fix a
term for each of these before you start, write it down, and use only that.

| English | What it means here | Do not confuse with |
| --- | --- | --- |
| deduction | reduces the **income** you are taxed on | credit |
| credit | reduces the **tax** you owe, dollar for dollar | deduction |
| standard deduction | the flat amount anyone may subtract | itemized deduction |
| itemize / itemized deduction | listing deductions individually instead | standard deduction |
| adjusted gross income (AGI) | the income figure the ceilings apply to | gross income, taxable income |
| marginal tax rate | the rate on your **top** dollar of income | average or effective rate |
| ceiling | the 60% / 50% / 30% / 20% upper limit | the 0.5% floor |
| floor | the 0.5% of AGI below which giving does not count | the ceilings |
| carryforward | unused deduction moves to later tax years | refund |
| written acknowledgment | the receipt the charity must issue | thank-you note, agreement |
| contemporaneous | obtained in time, before the filing deadline | modern, current |
| public charity | IRS classification of this organization | private foundation |
| filer | person who files a US federal return | informer, reporter |
| the work | the charity's programme activity | business, company |

"AGI" may stay as the Latin letters AGI inside table cells. That is preferable
to inventing a Burmese acronym a reader has never seen.

---

## 4. How the file works

### 4.1 Segments and blocks

The letter is 92 rendered lines in the source artwork, but a rendered line is
half a sentence, so it is a useless unit to translate. The package regroups
those 92 lines into **64 logical blocks**, then splits each prose block into
sentences. The result is **102 segments**, of which **87 need translation** and
**15 are reproduced exactly** (the organization's name, the domain, and the bare
figures in the table).

Segment ids run 001 to 102 and the `block` column tells you which block a
segment belongs to.

### 4.2 You may restructure inside a block, not across blocks

Burmese does not always want one sentence where English has one. **Within a
single block** you may move meaning between segments freely. If two English
sentences become one Burmese sentence, put the whole Burmese rendering in the
first segment's row and write `MERGED` in the second segment's row.

Do not move meaning between different blocks. Blocks land in different places on
the page.

### 4.3 Verbatim rows

Rows whose `kind` is `verbatim` or `figure` come pre-filled and must be left
exactly as they are:

* `Win's VPN Inc.` and `WIN'S VPN INC.` are a registered legal name. Do not
  translate or transliterate them.
* `winsvpn.org` is a domain.
* `$100`, `$1,000`, `12%`, `$8,500` and the rest of the bare table figures.

The checker fails the file if any of these changed.

### 4.4 Line length

Do not try to control where lines break. The build measures your text in Chrome,
which knows where Burmese words end, and re-wraps every block to fit its column.
Write natural Burmese and ignore the layout.

Do not insert zero-width spaces to force breaks. If your input method inserts
them, that is fine and the checker will report how many; it will not reject
them.

---

## 5. Two blocks that are not in the English letter

The English letter has no equivalent of these. Translate them like everything
else.

### `notice.governing` (segments 093 to 095)

The governing-language clause. Section 2.3 above. It is printed on the page in
Burmese **and** in English, so both a Burmese reader and an English-reading
reviewer can see it.

### `notice.scope` (segments 096 to 101)

This one matters more than its size suggests, and it is here because a previous
reviewer noticed the English letter never says it.

The whole letter describes **United States federal** tax rules. Those rules only
change what a person owes if that person files a United States federal income
tax return. Most people reading Burmese will not file one. For them, nothing in
this letter reduces any tax, and the four worked examples describe a situation
they are not in.

The note says so plainly, and then says a gift is still a gift. That last part
is not a sales pitch and must not be translated as one; it is there so a reader
does not conclude the organization was trying to mislead them.

This note is printed in a highlighted box near the top of the Burmese page,
above the "READ THIS FIRST" caveat, so a reader meets it before the US rules. A
short English gloss sits under it. The full English source is in
`donor-letter.segments.json`.

### Where these end up on the website

The donations section of winsvpn.org now carries a **Letter language** dropdown
above the letter. English is selected by default and is the only working option
until your translation lands. When Burmese is selected, the page shows the
Burmese letter image **and** prints the governing-language notice as ordinary
page text beside it, so that clause is readable without opening the image. Your
translation of `notice.governing` is what goes there.

---

## 6. What must not change, in either language

* Every tax figure and the source it comes from. See `DIGIT-CHECKLIST.md`.
* The "READ THIS FIRST" caveat that most filers get no itemized deduction.
* The honest framing throughout: what the letter cannot tell you, that tax-exempt
  status is not an IRS endorsement of the VPN product, that the recognition tiers
  do not exist yet, that the examples are illustrations and not predictions.
* No EIN anywhere. No street address anywhere. Both are deliberately absent from
  every public web surface and the checker fails the file if either appears.
* No em dashes, en dashes or any other long dash, in any language. Use a comma,
  a semicolon, a colon, or a new sentence. The checker fails the file on
  U+2014 EM DASH, U+2013 EN DASH, U+2015 HORIZONTAL BAR, U+2012 FIGURE DASH,
  U+2212 MINUS SIGN and the small and fullwidth variants. A plain hyphen
  (U+002D) is fine.

---

## 7. When you are finished

1. Save `donor-letter.my.csv` as UTF-8.
2. Run the mechanical checks:

   ```
   python3 check_translation.py donor-letter.my.csv
   ```

   It must print `0 FAIL`. It checks completeness, every required figure, every
   figure per block, Burmese numerals, long dashes, EIN and address patterns,
   verbatim rows, and whether anything is still sitting in English. It does
   **not** check meaning.

3. A second Burmese speaker, who has not seen your translation, should
   back-translate segments 001 to 030 and the whole of `callout.body`,
   `notice.governing` and `notice.scope` into English without looking at the
   English source. Compare that back-translation against the English. That is
   the step that caught all five defects in section 2.

4. Hand back the CSV. The owner runs the build and looks at the rendered page
   before anything is published.

Nothing is published until a human has read the rendered image.
