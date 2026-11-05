# Win's VPN Apple Submission Package

Last reviewed: 2026-08-25

This folder contains copy-ready App Store Connect material for the iOS and macOS
Win's VPN submissions. It deliberately contains no Apple credentials, private
keys, provisioning-profile identifiers, server credentials, account numbers, or
test customer secrets.

Release `1.0.17+34` has exactly two required Apple App Store artifacts: one iOS
IPA that embeds the modern single-target watchOS app, and one macOS App Store
PKG. A Developer ID macOS build is an optional, separately evidenced
distribution lane. It does not affect the required target count, ready/100,
freeze completeness, or App Store upload readiness. tvOS is post-release native
product work and is not an artifact, upload target, release blocker, or
readiness denominator for this release.

Authoritative Apple references:

- https://developer.apple.com/help/app-store-connect/create-an-app-record/add-a-new-app/
- https://developer.apple.com/help/app-store-connect/create-an-app-record/add-platforms/
- https://developer.apple.com/help/app-store-connect/reference/app-information/required-localizable-and-editable-properties/
- https://developer.apple.com/help/app-store-connect/reference/app-information/screenshot-specifications/
- https://developer.apple.com/help/app-store-connect/reference/app-information/app-privacy/

## Current Release State

Use the dated records in this folder (and, for the Apple engineering track,
`docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md`) only as historical technical
context. There is no current release-ready IPA or PKG for `1.0.17+34`.
`artifacts/release_candidate.json` records
`candidate_set_status=no_current_candidate` for the intended version/build
`1.0.17+34`. Both artifact entries stay unbound: empty path/hash/size, reserved
iOS/macOS bundle IDs, an embedded watchOS companion identity, and unbound Apple
Distribution signing slots. Historical `1.0.14+29` files live only under
`historical_non_authoritative` and must not be uploaded, attached, or reused as
owner-authorization evidence. Unsigned, ad-hoc, Apple Development, placeholder,
and stale build-29 identities fail closed.

Earlier physical-iPhone, signed-macOS, archive-privacy, source-gate, and
submission-validator results remain implementation evidence only. They are not
current candidate-bound runtime, custody, clean-install, Apple validation, or
upload evidence. A fresh Apple Distribution signed iOS IPA with the embedded
watchOS companion and a fresh Apple Distribution signed macOS App Store PKG
must be produced from the current frozen source, verified, and recorded before
any Apple release action can proceed. tvOS is not in this release.

## Folder Map

- `artifacts/release_candidate.json`: fail-closed candidate-status manifest.
  Current artifact entries are unbound `1.0.17+34` placeholders until a fresh
  signed iOS IPA with embedded watchOS and a signed macOS PKG exist. App Store
  IPA/PKG receipts must not claim Developer ID notarization.
- `artifacts/runtime_evidence.json`: pending current runtime evidence. It is
  not current `1.0.17+34` candidate-bound evidence.
- `metadata/en-US/`: customer-facing App Store metadata draft.
- `metadata/app_information.md`: shared App Store Connect app-information
  fields, including bundle IDs, SKU, category, and URLs.
- `metadata/pricing_availability.md`: pricing, release, availability, and
  future paid-plan draft.
- `review/ios_review_notes.txt`: App Review notes for the iOS build.
- `review/macos_review_notes.txt`: App Review notes for the macOS build.
- `review/app_review_information.md`: App Review contact/test instructions.
- `review/age_rating_answers.md`: age-rating questionnaire draft.
- `review/accessibility_evidence.md`: exact-candidate accessibility test
  evidence and an explicit list of claims that are not yet safe to publish.
- `review/export_compliance_facts.txt`: encryption/export-compliance facts to
  review before answering App Store Connect.
- `review/export_compliance_status.json`: fail-closed export-compliance status
  for 1.0.17+34. Unsigned artifacts may not carry an encryption declaration.
- `review/apple_tv_post_release_scope.json`: explicit non-shipping Apple TV
  contract. tvOS is not a listing, privacy, export, signing, upload, or receipt
  surface for this release.
- `review/privacy_answers.md`: App Privacy answers aligned with the current
  archive manifests and website policy.
- `review/privacy_label_manifest.json`: machine-checkable privacy-label
  evidence tying App Store privacy answers to source `PrivacyInfo.xcprivacy`
  files, archived privacy reports, Apple purchase-gate behavior, and excluded
  tracking/analytics dependencies.
- `review/owner_signoff.json`: explicit owner-review decision manifest. It is
  currently a guarded draft: `submission_approved` is false, credentials and
  upload stay unauthorized, export-compliance remains pending, and there is no
  current candidate set. Screenshot inventory (`screenshot_set`) is still
  pending in this manifest until final screenshots are captured from the exact
  `1.0.17+34` candidates; live portal privacy labels still need a later App
  Store Connect update. Future metadata, screenshot, privacy, or artifact changes require
  refreshing the exact approved values.
- `review/owner_review_packet.md`: human-readable owner review packet with the
  exact metadata, screenshots, artifact hashes, runtime evidence, proposed
  approval values, and guarded upload commands.
- `review/rollout_readiness.json`: machine-checkable public-rollout blocker
  manifest that ties owner sign-off, App Store Connect API-key, upload, Apple
  review, metadata/privacy, and macOS root-install gates to concrete local
  evidence logs.
- `screenshots/screenshot_plan.md`: required screenshot sizes and capture plan.
- `testflight/test_information.md`: TestFlight beta description, what-to-test
  copy, feedback email, and demo-access notes.

Run `python3 tools/validate_apple_submission_package.py` before copying this
material into App Store Connect. The validator checks App Store text limits,
HTTPS URL syntax, live URL reachability/content for support/marketing/privacy
pages, duplicate/empty keywords, required review/submission files, required
App Store field markers, release-candidate artifact hashes/sizes, release
verification-log proof markers, signed macOS and physical-iPhone runtime
evidence, privacy-label manifest consistency against source privacy manifests
and archived privacy reports, default Apple purchase-gate behavior, excluded
tracking/analytics dependencies, owner sign-off schema, owner review-packet
content, rollout-readiness blocker consistency, candidate screenshot dimensions,
and secret-like marker hygiene. Default draft validation stays fail-closed
pending: it does not require a current signed IPA/PKG or a live App Store
Connect privacy match. `--release-ready` and upload remain refused until real
Apple Distribution identities, live portal privacy match, export approval, and
owner approval exist.

Run `python3 tools/apple_store_listing_metadata.py` to review listing, privacy,
export-compliance, recorded signing identities, embedded watchOS, and the
non-shipping Apple TV contract for `1.0.17+34`.

Run `python3 tools/validate_apple_owner_signoff.py --print-owner-approval-template`
to print a no-write JSON copy-aid for the exact proposed owner approval values
from `review/owner_review_packet.md`. It does not store any App Store Connect
credentials.

Run `python3 tools/validate_apple_owner_signoff.py --dry-run-owner-approval` to
validate those exact packet values inside a temporary approved manifest without
modifying the real `review/owner_signoff.json`.

Run `python3 tools/apple_app_store_connect_release_status.py` with the three
external App Store Connect authentication environment variables to perform a
read-only live audit. It verifies the universal app identity, both platform
version records, localized metadata, build processing, screenshots, review
details, privacy URL, all 175 free price entries, and the separate storefront
availability resource, plus Apple encryption-declaration review states, without
printing or storing authentication material. It also verifies that the current
  zero accessibility declarations match the current release decision, and
  reports all existing App Review submission states.
The narrowly scoped `--set-privacy-url --confirm-apple-id 6789417002` action
updates only the approved public privacy URL and immediately re-audits it.
The `--sync-review-details` action uses temporary
`WINS_APPLE_REVIEW_CONTACT_*` environment variables to create or update the
approved no-demo-account review instructions for both platforms without
writing the contact name or any credential into the repository or output.

Run `python3 tools/apple_upload_exact_release_candidates.py` without action
flags to verify frozen IPA and PKG hashes without uploading. With the current
invalidated artifact entries, this command is expected to refuse rather than
qualify the old `1.0.14+29` files. Its guarded
`--preflight` and `--upload` modes additionally require exact Apple ID/hash
confirmations, an approved owner manifest, the complete submission validator,
the matching macOS clean-install gate, and a live external-key authentication
probe. This is the release upload lane for approved candidates because it sends
the exact local IPA/PKG bytes instead of rebuilding or re-exporting an archive.

Run `python3 tools/apple_upload_exact_screenshots.py` without action flags to
verify both owner-reviewed PNG hashes and dimensions without creating any Apple
resource. Its guarded upload mode requires the approved owner manifest and
exact hash confirmations, refuses duplicate/replacement uploads, follows
Apple's returned byte-range operations, commits the required whole-file MD5,
waits for asynchronous processing to reach `COMPLETE`, and removes only
reservations created by the same failed run.

Run `python3 tools/apple_attach_processed_builds.py` after Apple processes both
binary uploads. The guarded lane requires the same exact IPA/PKG hash
confirmations, owner approval, clean-install evidence, and live authentication;
  it derives the current version/build from the hash-pinned release manifest,
  accepts exactly one nonexpired `VALID` matching build per platform, preserves
  an already-correct selection, and refuses to replace a different attached
  build.

Run `python3 tools/apple_set_all_storefront_availability.py` only after the
Account Holder's DSA trader information is verified. Its guarded action
requires exact approval of `175` current Apple territories and the literal
scope confirmation `ALL_175_ACTIVE_STOREFRONTS`, re-verifies all 175 prices are
free, creates immediate non-preorder availability, includes future territories,
and refuses any existing partial or incompatible configuration.

Run `python3 tools/apple_submit_for_app_review.py --preflight` after build
attachment, availability, DSA verification, and encryption approval. The tool
models Apple's platform-neutral App Store Connect API 4.4 submission as exactly
two App Store version items, verifies the accepted encryption declaration is
linked to both selected builds, and refuses partial or unrelated active review
content. `--prepare` creates but does not submit that exact record; `--submit`
  requires a separate literal confirmation derived from the manifest-pinned
  version/build. After fresh `1.0.17+34` candidates replace the invalidated
  records, the required confirmation will be
  `SUBMIT_IOS_AND_MACOS_1_0_16_BUILD_33` before setting `submitted=true`. That
  literal is not authorization while the current candidate set remains
  invalidated.

## Still Needs App Store Connect Entry

- Universal purchase was approved on 2026-07-10. The macOS host and
  PacketTunnel identifiers now use the shared iOS identifiers. Earlier signed
  macOS package and development-runtime checks are historical and do not qualify
  release `1.0.17+34`. The local keychain currently has Apple Distribution and
  Developer ID Application identities, but no `3rd Party Mac Developer
  Installer` or `Developer ID Installer` identity. A current macOS App Store PKG
  and Developer ID installer are therefore blocked; no current package custody,
  clean-install, Apple validation, owner approval, upload, processing,
  attachment, or App Review is claimed.
- The universal iOS/macOS app record exists under Apple ID `6789417002`.
- Local App Privacy answers are drafted for Coarse Location, User ID,
  Device ID, and Product Interaction as linked, non-tracking App Functionality
  data. Purchase History is not collected by the current Apple app. Live App
  Store Connect answers still list Purchase History and omit Product Interaction
  and still need an owner portal correction at the next submission. Privacy
  labels are not claimed
  synchronized or published for `1.0.17+34`. The public privacy link in local
  metadata is `https://www.winsvpn.org/privacy/`.
- App Store Connect API access is historically approved, but the current release
  shell does not have a complete external key-path/key-ID/issuer-ID set. Upload
  remains blocked until all three owner-only values are configured and fresh live
  API authentication passes against Apple ID `6789417002`.
- App Review contact details, no-demo-account settings, and platform-specific
  review notes are configured and live-verified for both version records.
- Apply the already approved availability selection to all 175 storefronts;
  the free price schedule is configured and live-verified for all 175.
- iOS and macOS upload/submission in App Store Connect.
- Final export-compliance answers selected in App Store Connect.
- Account Holder Digital Services Act trader declaration and verification in
  App Store Connect Business before EU distribution.
- App Accessibility remains deliberately unpublished for build `34`; the
  evidence file records scoped passes without claiming unverified workflows.
- Any paid subscription or In-App Purchase plan. The current Apple build avoids
  external purchase links by default.
