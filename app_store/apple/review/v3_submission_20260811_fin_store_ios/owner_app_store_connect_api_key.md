# What needs the owner's App Store Connect API key - Winn v3 (fin_store_ios, 2026-08-11)

**Prepared by lane `fin_store_ios` on 2026-08-11. PREPARE ONLY - nothing was
uploaded, submitted, staged for upload, or re-signed; no credential material was
read, printed, or stored.**

The submission **package** needs no key. This enumerates (a) what the API key
unlocks when the owner chooses to run it, (b) the exact owner steps, and (c) the
things the API key does **not** unlock - several of which currently block an
upload more than the key does.

## 1. What the API key is for

Every operative App Store Connect command (`altool --validate-app`,
`--upload-app`, `--list-providers`, and the repo upload/audit tooling) signs its
requests with an App Store Connect **API key** - a `.p8` private key plus Key ID
and Issuer ID. Only the Account Holder (Admin) can generate it, which is owner-
gated. The App record lives under Apple ID **`6789417002`** (bundle
`org.winsvpn.app`).

## 2. Exactly what the owner must do (in order)

1. **Create the key** - appstoreconnect.apple.com -> Users and Access ->
   Integrations -> App Store Connect API -> **Generate API Key**. Name it
   `wins-release-upload`, set **Access = App Manager** (upload needs App Manager
   or Admin), then **Generate**.
2. **Download the key once** - the next screen shows it a single time. Download
   the `.p8` (basename is literal `AuthKey` + `_` + the ten-character Key ID,
   with `.p8` extension) and copy the **Key ID** (10-char) and the **Issuer ID**
   (UUID at the top of the same Integrations page).
3. **Install it privately, outside the repo, owner-only perms** (tooling refuses
   a key inside the repo, a symlink, or any group/world bits):

   ```
   mkdir -p "/Users/owner/Library/Application Support/WinsVPN/asc"
   chmod 700 "/Users/owner/Library/Application Support/WinsVPN/asc"
   # place the downloaded .p8 there, then:
   chmod 600 "/Users/owner/Library/Application Support/WinsVPN/asc/<downloaded .p8>"
   ```

   The uploader/probe read this path literally:
   `/Users/owner/Library/Application Support/WinsVPN/asc/<the .p8 from step 2>`.
4. **Supply three env vars** to the tool session (never commit them):
   `WINS_APPLE_AUTHENTICATION_KEY_PATH` (the `.p8` path),
   `WINS_APPLE_AUTHENTICATION_KEY_ID` (ten-char Key ID),
   `WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID` (Issuer UUID).

## 3. With the key installed, these unlock (read-only -> upload, in order)

1. `tools/apple_app_store_connect_auth_probe.py` - live auth probe (Apple ID
   6789417002, bundle org.winsvpn.app).
2. `tools/apple_app_store_connect_release_status.py` - read-only live audit.
3. `tools/apple_upload_exact_release_candidates.py --preflight` then `--upload`
   - hash-pinned upload of a **new** frozen 1.0.15+30 candidate pair (none
   exists yet - see Section 4); refuses any sha mismatch.
4. `tools/apple_upload_exact_screenshots.py --upload` - needs the re-shot
   screenshots from the current build (the existing set is superseded).
5. `tools/apple_attach_processed_builds.py`,
   `tools/apple_set_all_storefront_availability.py`,
   `tools/apple_submit_for_app_review.py` - post-upload gates.

## 4. What the API key does NOT unlock (separate owner actions, in order)

- **A 1.0.15+30 rebuild/re-freeze.** The key does not sign. The only signed iOS
  App Store IPA is the stale `1.0.14+29`; the live tree is `1.0.15+30` and
  `build/apple/exports/` has no iOS export. This needs the **Apple Distribution**
  signing identity back in the keychain (only `Apple Development` is present),
  then `tools/build_apple_release_candidates.sh`, then owner approval of
  `owner_signoff.json` for the new hashes, then confirm in ASC that nothing above
  build 29 has already been processed.
- **No source privacy-manifest edit remains.** On-disk `ios/Runner` and
  `macos/Runner` `PrivacyInfo.xcprivacy` are already reconciled to exactly
  **4** collected types: Coarse Location, Device ID, User ID, and Product
  Interaction, with no `NSPrivacyCollectedDataTypePurchaseHistory` (Purchase
  History was removed from source on 2026-08-23; Product Interaction was added
  on 2026-08-24 - see `privacy_label_v3.md` Section 3). The binary will match the
  corrected App Privacy answers; nothing on disk needs editing for privacy.
- **Export/encryption questionnaire + DSA trader verification** - answered in the
  ASC console by the owner (+ counsel for export classification); see
  `export_compliance_v3.md`.
- **Re-shot screenshots** from the current build.
- **Reconciling the live App Privacy answers in ASC** (last synced 2026-07-11,
  still 4 types with Purchase History and no Product Interaction) to match the
  already-corrected manifests: remove Purchase History and add Product
  Interaction - a console action, not a key action.
- The five signing certificates are a **keychain** gap, not an API-key gap.

## 5. The honest bottom line

The API key alone cannot produce an upload today: there is **no current signed
candidate** to upload. The shortest real path:

1. Owner restores the **Apple Distribution signing identity** in the keychain.
2. Owner creates + installs the **ASC API key** (Section 2).
3. Reconcile the **live App Privacy answers in ASC**: remove Purchase History
   and add Product Interaction to match the already-corrected manifests (the
   binary and manifests agree on 4 types; only the console is stale).
4. Rebuild / re-freeze **1.0.15+30**, owner-approve `owner_signoff.json`.
5. Delete the stale pending-owner guard log named in
   `rollout_readiness.json` (it references a `/tmp` path outside the repo).
6. Probe -> preflight -> upload -> submit (using the new private key).

The API key is the **second** owner credential; the Apple Distribution signing
identity is the **first**.