# Demo account determination - v3 release (iOS)

**Prepared by lane `fin_store_ios` on 2026-08-10. PREPARE ONLY.**

## Determination

**Demo account required: NO.**

- App Review contact is configured with the no-demo-account path
  (`app_review_information.md` -> "Demo account required: No."), live-verified in
  App Store Connect on the historical record.
- Reviewers test via **Try Free Server**: free seeded access, no paid account
  number, password, private key, or server credential.
- Verified in-tree: `Try Free Server` appears in `lib/main.dart` and the review
  notes already instruct reviewers to use it; the owner packet's
  `review_contact_and_notes` decision approves this path.

## Provision for a reviewer account - only if the free pool dries up

The owner may, before submission, create a **single review-only account number**
in App Store Connect (App Review Information -> "demo account" fields) and provide
it in the Review Notes. That is an owner action in the ASC console and does not
require any code change. It is strongly preferred to keep reviewer access
credential-free (Try Free Server) because:
- no review-centric account exists in the codebase (none found in source);
- a credential in review notes is additional material that must be guarded;
- the no-demo-account setting is already live on the APP record and verified.

## Rule for the gate

- If v3 submission stays on Try Free Server: leave "Demo account required: No"  -
  no change.
- If the free pool proves unavailable at review time, the owner adds the
  review-only account number via ASC; that is the only case where a demo account
  is "needed", and it is a console-side addition.
- NEVER commit a review credential to the repo.