# v3 App Store submission - package inventory & readiness (fin_store_ios, 2026-08-11)

**Prepared by lane `fin_store_ios` on 2026-08-11. PREPARE ONLY - nothing was
uploaded or submitted.** This indexes the complete v3 iOS submission package:
what is ready, what is gated, and what remains open.

## Package contents (this directory, `v3_submission_20260811_fin_store_ios/`)

| file | what it is |
|---|---|
| `privacy_label_v3.md` | corrected App Privacy answers (4 declared types incl Product Interaction) + the Purchase-History reconciliation |
| `export_compliance_v3.md` | encryption/export fact sheet + recommended questionnaire answers (legal-rvw) |
| `review_notes_v3_ios.md` | reviewer-facing VPN explanation + test steps |
| `demo_account_v3.md` | demo-account determination: none (Try Free Server) |
| `owner_app_store_connect_api_key.md` | exactly what needs the owner's API key + prior blockers |

## Core record facts (verified this run)

- Apple ID **6789417002**; app bundle `org.winsvpn.app`; extension
  `org.winsvpn.app.PacketTunnel`.
- In-tree version **1.0.15+30** (`pubspec.yaml`). No signed v3 iOS IPA exists  -
  only the stale `1.0.14+29`; `build/apple/exports/` has no iOS export.
- Privacy manifests: `ios`+`macos` Runner = 4 declared types (Coarse Location,
  Device ID, User ID, Product Interaction; Purchase History removed from source).
  PacketTunnel = 0 collected.
  Watch companion = 0 collected. Tracking false/empty everywhere.
  `ITSAppUsesNonExemptEncryption` absent (Runner + PacketTunnel).

## Ready now (no gating)

- Demo account: **No** - reviewers use Try Free Server (matches live ASC).
- Review-notes VPN explanation (engine-neutral wording; the v3 first-party
  paragraph is held behind the gate).

## Gated behind a signed v3 build (does not exist yet)

- The first-party winn3 paragraph in the **review notes** and the **privacy
  justification** - enable only when the exact submitted binary carries the
  winn3 datapath (suite `winn3-x25519-mlkem768-chacha20poly1305-sha256`).
- Release-note/what's-new copy naming **Version 3** must match the submitted
  binary's negotiated session line (or the app's own "Verify No Log Policy" can
  read as contradicting the store).

## Open items the owner must close before/at submission

1. **Apple Distribution signing identity** in the keychain (only Apple
   Development present) -> rebuild/re-freeze **1.0.15+30** -> approve
   `owner_signoff.json` -> confirm nothing above build 29 processed in ASC.
2. **Create + install the App Store Connect API key** (Section 2 of the API-key doc).
3. **Source privacy manifests already reconciled** - re-measured on 2026-08-25:
   `ios`+`macos` Runner now declare exactly 4 types (Coarse Location, Device
   ID, User ID, Product Interaction); Purchase History is already removed from
   source (2026-08-23) and Product Interaction added (2026-08-24). No manifest
   edit remains. The outstanding privacy action is the live ASC console
   reconciliation (next step).
4. **ASC console:** remove Purchase History from the live App Privacy answers
   (last synced 2026-07-11, still 4).
5. **Export/encryption questionnaire + DSA trader verification**, with counsel
   for the export classification (France declaration if distributed there).
6. **Re-shot screenshots** from the current build (existing set superseded).
7. Clear the stale pending-owner guard log named in `rollout_readiness.json`
   (a `/tmp` path).

## Shortest path to a submittable v3 build

signing identity restored -> ASC API key created/installed -> ASC console App
Privacy answers reconciled (drop Purchase History, add Product Interaction;
source manifests already done) -> rebuild/freeze 1.0.15+30 -> owner signoff ->
probe -> preflight -> upload -> submit. The API key is the second owner
credential; signing is the first.