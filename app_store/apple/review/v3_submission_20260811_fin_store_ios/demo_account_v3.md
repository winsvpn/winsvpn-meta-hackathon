# Demo account determination - Winn v3 (fin_store_ios, 2026-08-11)

**Prepared by lane `fin_store_ios` on 2026-08-11. PREPARE ONLY.**

## Determination: **No demo account is required.**

- App Review contact is configured with the no-demo-account path
  (`app_review_information.md` -> "Demo account required: No."), and the owner
  packet's review-contact decision approves it.
- Reviewers test via **Try Free Server** - free seeded access, no paid account
  number, password, private key, or server credential.
- Verified in-tree: `Try Free Server` appears in the app flow and the review
  notes (v3 and current) instruct reviewers to use it.

## The only case where a demo account becomes "needed"

If the reviewer-specific free pool is ever unavailable at review time, the owner
may create a **single review-only account number** in App Store Connect (App
Review Information -> demo-account fields) and provide it in the Review Notes.
That is an **owner action in the ASC console** and requires no code change and
no credential in this repo.

## Rule for the gate

- If v3 submission stays on Try Free Server: leave "Demo account required: No"  -
  no change.
- If a review-only account is ever added: it is a console-side addition only;
  **never commit a review credential to the repo.**