# Browser extension store-listing drafts

These are local drafts for the Chrome Web Store, Microsoft Edge Add-ons, and
Firefox Add-ons. They do not prove package upload, review, approval, listing
publication, assigned store IDs, or native-host registration. Status remains
BLOCKED until a real upload receipt binds the exact unsigned package bytes for
that store. Missing owner or store evidence stays BLOCKED. Do not add an
artifact receipt, a store URL, a screenshot file, or a completed checklist
item until the exact package is independently verified and the corresponding
portal action has actually completed.

Chrome and Edge are distinct listing identities. The Chrome Web Store name,
upload target `chrome-extension-package`, unsigned ZIP, and receipt are not
Microsoft Edge Add-ons evidence. The Microsoft Edge Add-ons name, upload target
`edge-extension-package`, unsigned ZIP, and receipt are not Chrome Web Store
evidence. Firefox Add-ons uses upload target `firefox-extension-package` and the
declared Gecko ID `companion@winsvpn.org`. That ID is not Mozilla review and
not an AMO approval. One browser's archive or receipt is not another browser's
evidence.

The current Win's VPN application release is `1.0.17+34`. The browser
extensions carry the application marketing version, `1.0.17`, generated from
`pubspec.yaml` at build time (OI-42); a pre-release pubspec version builds no
store package. Native-host linkage stays with desktop app `1.0.17+34` and host
name
`org.winsvpn.bridge`. Chrome uses owner-authenticated draft ID
`lnehjdblendkagjbmdclepjalahdhbbn`; Edge uses owner-authenticated draft ID
`glgihadopbjoandhoihghddecoibcldf`. Their native-host origins are bound to
those exact identities. Neither draft ID proves an upload, review, approval,
or public listing. The release tooling fails closed if either ID drifts from its
native-host allowlist. Firefox uses the declared Gecko ID in
`allowed_extensions`.

Packaged JavaScript is a whitespace-only size transform of authored
`extension/src`. Identifier mangling, control-flow concealment, and source maps
are forbidden. Firefox `wins-vpn-companion-firefox.xpi` is a distinct unsigned
copy of `wins-vpn-companion-firefox.zip`, not a hardlink and not Mozilla-signed.
Reviewer-source disclosure, store category, Firefox license, privacy-practices
portal answers, and screenshots stay owner-blocked. Candidate hashes stay held
while `release_candidate.json` reports `no_current_candidate`.

Upload authorized: no. Publication authorized: no. Credentials authorized: no.
Listing evidence: BLOCKED. Store evidence: BLOCKED. A listing upload receipt
may bind exact unsigned ZIP or XPI bytes and still leave every store BLOCKED.
`upload_authorized` stays false without owner evidence. This directory never
uploads.

This directory may contain only these ASCII files:

- `README.md`: this file.
- `chrome.md`: Chrome Web Store copy and pre-submission checklist.
- `edge.md`: Microsoft Edge Add-ons copy and pre-submission checklist.
- `firefox.md`: Firefox Add-ons copy and pre-submission checklist.
- `store_identity.json`: machine-checkable owner-authenticated draft IDs, Gecko
  ID, native-host allowlists, and unsigned archive names.
- `owner_signoff.json`: blocked owner-signoff record for 1.0.17+34.
- `privacy_label_manifest.json`: fail-closed privacy questionnaire. Portal
  answers stay BLOCKED.
- `release_candidate.json`: unbound 1.0.17+34 candidate set. Held hashes only.

No screenshot binaries, promo tiles, unbound 32-letter store IDs, or upload
receipts belong here. Screenshot and metadata completeness stays BLOCKED until
those artifacts exist as separately recorded portal evidence.
