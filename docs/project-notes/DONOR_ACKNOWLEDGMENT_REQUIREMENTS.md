# Donor Acknowledgment Requirements

What a Win's VPN Inc. donation acknowledgment must contain so that it is usable
by the donor at filing time.

Authority: IRS Publication 1771, *Charitable Contributions — Substantiation and
Disclosure Requirements* (Rev. 11-2023),
<https://www.irs.gov/pub/irs-pdf/p1771.pdf>. Underlying law: IRC 170(f)(8) and
Reg. 1.170A-13(f) (written acknowledgment), IRC 170(f)(17) and Reg. 1.170A-15
(recordkeeping), IRC 6115 and Reg. 1.6115-1 (quid pro quo disclosure), IRC 6714
(penalty), IRC 513(h)(2) (low-cost articles).

Status: written 2026-08-03 as a build spec for the planned certificate of
recognition and for the existing emailed donation receipt. Not legal or tax
advice; have counsel or a CPA review the final template.

---

## 1. Why this matters

A donor **cannot claim a deduction** for any single contribution of $250 or more
without a contemporaneous written acknowledgment from the charity. The
organization is not penalized for failing to provide one — the donor simply
loses the deduction. An acknowledgment that omits a required element is
worthless to the donor at filing time, which is why this list exists.

Pub. 1771: a donor "cannot claim a federal income tax deduction for any single
contribution valued at $250 or more unless the donor obtains a contemporaneous
written acknowledgment."

---

## 2. Required elements for a single gift of $250 or more

All of the following must appear:

1. **The name of the organization.** Use the legal name: *Win's VPN Inc.*
   (Including the EIN, 42-3223917, is not required but is helpful and harmless.)
2. **The amount of the cash contribution.** The dollar figure, e.g. `$250.00`.
3. **A description of any non-cash contribution** — description only. The
   charity must **not** state a value for donated property; valuing it is the
   donor's job. (Not applicable to card/PayPal cash gifts.)
4. **One of the following statements, and this is the element most often
   missed:**
   - If nothing was given in return: *"No goods or services were provided in
     exchange for this contribution."*
   - If something was given in return: a **description** of the goods or
     services **and a good faith estimate of their fair market value**.
   - If the only benefit was an intangible religious benefit: a statement
     saying so. **Not applicable to Win's VPN Inc.**

The donor's Social Security number or taxpayer ID is **not** required and should
**not** be collected or printed.

**Strongly recommended although not on the statutory list:** the **date of the
contribution**. It is a required element of the separate recordkeeping rule for
*any* monetary contribution (name of organization, date, amount), so a template
that omits the date fails the under-$250 rule even if it passes the $250 rule.
Include it always.

## 3. Timing — "contemporaneous"

The donor must **receive** the acknowledgment on or before the earlier of:

- the date the donor files their individual federal return for the year of the
  contribution, **or**
- the due date of that return, including extensions.

Pub. 1771 notes that charities typically send acknowledgments no later than
**January 31 of the year following the donation**. Send on receipt of payment
and again in an annual summary; do not wait.

## 4. Format

- Letters, postcards, and computer-generated forms are acceptable.
- **Email is explicitly acceptable.** Pub. 1771: an organization "can provide
  the acknowledgment electronically, such as via an email addressed to the
  donor."
- One acknowledgment per gift, **or** a single annual summary covering several
  gifts of $250 or more. Either is fine.
- The donor keeps it; it is not attached to the return.

## 5. The aggregation trap

**Separate contributions of less than $250 are not aggregated.** A donor who
gives $50 twelve times has made twelve sub-$250 gifts, not one $600 gift, and
the $250 rule never applies to them — the ordinary recordkeeping rule does
(bank record, or a written communication showing organization name, date, and
amount).

Practical consequence: an annual summary is a convenience, not a rescue. It
cannot retroactively turn small gifts into a $250 gift, and it must still show
each qualifying gift individually so the donor can identify which single gifts
were $250 or more. Recurring monthly donors are the group most affected.

## 6. Quid pro quo disclosure — separate rule, separate threshold

If a donor makes a payment of **more than $75** that is partly a contribution
and partly payment for goods or services, the charity **must** furnish a written
disclosure statement that:

- informs the donor that the deductible amount is limited to the excess of the
  amount contributed over the value of the goods or services received, **and**
- gives the donor a good faith estimate of the fair market value of those goods
  or services.

It must be furnished at solicitation or at receipt, in writing, and "in a manner
that is likely to come to the attention of the donor" — Pub. 1771 specifically
warns that small print inside a larger document may not qualify.

**Penalty: $10 per contribution, capped at $5,000 per fundraising event or
mailing**, unless failure was due to reasonable cause.

### Token / insubstantial benefit exception (this is what protects the planned badges)

No disclosure is required, and the contribution stays fully deductible, where
benefits are of insubstantial value. Benefits are insubstantial if the payment
occurs in the context of a fundraising campaign, the charity tells the donor the
deductible amount, and **either**:

- the fair market value of what the donor receives is not more than the lesser
  of **2% of the payment** or **$139**; **or**
- the payment is at least **$69.50**, the only items provided bear the
  organization's name or logo, and their aggregate cost is within the
  "low-cost article" limit of **$13.90**.

Those three figures are the **2026** inflation-adjusted amounts from
**Rev. Proc. 2025-32, section 3.33** (<https://www.irs.gov/pub/irs-drop/rp-25-32.pdf>).
They change annually — the figures printed in Pub. 1771 (Rev. 11-2023) are the
2023 amounts ($139 was $125, $69.50 was $62.50, $13.90 was $12.50). **Re-check
the revenue procedure each year.**

### Applying this to the planned badge and certificate

A digital badge and a certificate of recognition are recognition, not goods or
services with a market. Treated as recognition of insubstantial value, they
leave the contribution fully deductible and require no quid pro quo disclosure.
To keep that treatment:

- Never describe a badge or certificate as something the donor **receives in
  exchange for**, **gets for**, or **unlocks with** a donation. Write
  *"in recognition of"*.
- Never attach anything with a real market price to a tier — no VPN account, no
  plan upgrade, no extra devices, no priority support, no merchandise. Any of
  those converts the gift into a quid pro quo contribution, reduces the
  deduction by its fair market value, and triggers the >$75 written disclosure
  requirement for essentially every donor.
- Keep the acknowledgment's "no goods or services were provided" statement
  intact. If a tier ever does carry a benefit with real value, that sentence
  becomes false and the template must change to a description plus a good faith
  estimate.

---

## 7. Assessment of the current emailed donation receipt

The website states: *"Donation receipts are sent by email after payment."* The
FAQ hedges further: *"Donation receipts and account emails are sent through the
service email system when configured."*

**Finding: the current receipts most likely do NOT satisfy the $250 rule.**
Flagging this as a real defect, not a theoretical one.

Basis for the finding:

1. No donation receipt or acknowledgment template exists anywhere in the
   canonical web codebase (`source/wins_vpn/web/`). There is no template to
   audit, which means no template was deliberately written against Pub. 1771.
2. Payments are processed by PayPal. A PayPal transaction confirmation is a
   **payment record from the processor**, not a written acknowledgment **from
   the charity**. It satisfies the ordinary recordkeeping rule for gifts under
   $250 (it shows payee, date, amount) but it is not a charity acknowledgment.
3. Decisively: a payment confirmation has no reason to contain the sentence
   *"No goods or services were provided in exchange for this contribution."*
   That sentence is element 4 above and is mandatory. Without it, the document
   is not a valid contemporaneous written acknowledgment and a donor of $250 or
   more cannot substantiate the deduction.
4. The FAQ's "when configured" wording suggests the receipt path may not be
   fully live, which would mean some donors received nothing at all.

**Consequence:** any donor who has given $250 or more since the June 11, 2026
effective date of exemption may currently be unable to substantiate that gift.

### Recommended remediation

1. Build a proper acknowledgment template containing elements 1–4 in section 2
   plus the contribution date, and send it from a Win's VPN Inc. address
   (SMTP2GO) rather than relying on PayPal's confirmation.
2. Retroactively issue acknowledgments to every donor of $250 or more since
   2026-06-11. This is still well inside the contemporaneous window for the
   2026 tax year (returns are not due until 2027), so it is fully fixable now
   and will not be fixable later.
3. Send an annual summary each January covering the prior calendar year, listing
   each gift separately with its date and amount.
4. Verify that the receipt path is actually configured and sending, and remove
   the "when configured" hedge from the FAQ once it is.
5. Have the final template reviewed by a CPA or nonprofit counsel before it goes
   out at volume.

---

## 8. Reference template

Plain text, no benefits provided — the normal case:

```
Win's VPN Inc.
EIN 42-3223917

Thank you for your contribution of $250.00, received by Win's VPN Inc.
on August 3, 2026.

No goods or services were provided in exchange for this contribution.

Win's VPN Inc. is recognized by the Internal Revenue Service as exempt
from federal income tax under Internal Revenue Code Section 501(c)(3),
effective June 11, 2026. Contributions are tax-deductible to the extent
allowed by law. Deductibility depends on your own circumstances, and
Win's VPN Inc. does not provide tax advice. Please retain this
acknowledgment for your records; do not attach it to your return.
```

If something of value ever is provided, replace the "No goods or services"
sentence with, for example:

```
In recognition of your contribution we provided [description], which we
estimate in good faith to have a fair market value of $[amount]. The
amount of your contribution that is deductible for federal income tax
purposes is limited to the excess of the amount contributed over the
value of the goods or services provided, which is $[difference].
```

---

## 9. Sources

- IRS Publication 1771, *Charitable Contributions — Substantiation and
  Disclosure Requirements* (Rev. 11-2023) —
  <https://www.irs.gov/pub/irs-pdf/p1771.pdf>
- IRS, *Charitable contributions: Written acknowledgments* —
  <https://www.irs.gov/charities-non-profits/charitable-organizations/charitable-contributions-written-acknowledgments>
- Rev. Proc. 2025-32, section 3.33 (2026 insubstantial benefit and low-cost
  article amounts) — <https://www.irs.gov/pub/irs-drop/rp-25-32.pdf>
- IRS Publication 526, *Charitable Contributions* —
  <https://www.irs.gov/publications/p526>
- IRS Topic no. 506, *Charitable contributions* —
  <https://www.irs.gov/taxtopics/tc506>
