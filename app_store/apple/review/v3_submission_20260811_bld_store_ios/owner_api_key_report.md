# What needs the owner's App Store Connect API key

**Prepared by lane `bld_store_ios` on 2026-08-11.** This is the precise,
in-order account of the only thing that genuinely needs the owner to act on an
App Store Connect **API key** - and what that key does and does **not** unlock.

The submission package itself needs **no** key. **No credential operation was
performed and nothing was submitted.** This report only enumerates what the
upload & live-audit tooling requires when the owner chooses to run it.

---

## 1. What the key is for

Every operative App Store Connect command (`altool --validate-app`,
`--upload-app`, `--list-providers`, and the repo upload/audit tools) signs its
requests with an App Store Connect **API key** - a `.p8` private key plus two
identifiers (Key ID, Issuer ID). Only the Account Holder (Admin) can generate it,
which is why it is owner-gated and not a lane action. The App record for this
account lives under Apple ID **`6789417002`** (bundle `org.winsvpn.app`).

## 2. Exactly what the owner must do (in order)

1. **Create the key** - appstoreconnect.apple.com -> Users and Access ->
   Integrations -> App Store Connect API -> **Generate API Key**. Name it
   `wins-release-upload`, set **Access = App Manager** (upload requires App
   Manager or Admin), then **Generate**.
2. **Download the key once** - the next screen shows it a single time. Download
   the `.p8` (its basename is the literal prefix `AuthKey`, an underscore, and
   the ten-character Key ID, with a `.p8` extension) and copy the **Key ID**
   (10-char alphanumeric) and the **Issuer ID** (UUID shown at the top of the
   same Integrations page).
3. **Install it privately, outside the repo, owner-only perms** (the tooling
   refuses a key inside the repo, a symlink, or any group/world bits):

   ```
   mkdir -p "/Users/owner/Library/Application Support/WinsVPN/asc"
   chmod 700 "/Users/owner/Library/Application Support/WinsVPN/asc"
   # place the downloaded .p8 there, then:
   chmod 600 "/Users/owner/Library/Application Support/WinsVPN/asc/<downloaded .p8 file>"
   ```

   Expected key path that the probe and uploader check literally:
   `/Users/owner/Library/Application Support/WinsVPN/asc/<the .p8 file named per step 2>`

4. **Supply three environment variables** to the tool session (never commit
   them): `WINS_APPLE_AUTHENTICATION_KEY_PATH` (the `.p8` path above),
   `WINS_APPLE_AUTHENTICATION_KEY_ID` (the ten-character Key ID), and
   `WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID` (the Issuer UUID), each assigned in
   the usual `export VAR value` form.

## 3. With the key installed, these unlock (read-only -> upload, in order)

1. `tools/apple_app_store_connect_auth_probe.py` - live auth probe (expects
   Apple ID 6789417002, bundle org.winsvpn.app).
2. `tools/apple_app_store_connect_release_status.py` - read-only live audit.
3. `tools/apple_upload_exact_release_candidates.py --preflight` then `--upload`
   - the guarded, hash-pinned upload of a **new** frozen 1.0.15+30 candidate
   pair (none exists yet - see Section 4), refusing any sha mismatch.
4. `tools/apple_upload_exact_screenshots.py --upload` - needs the re-shot
   screenshots from the current build (the existing set is superseded).
5. `tools/apple_attach_processed_builds.py`,
   `tools/apple_set_all_storefront_availability.py`,
   `tools/apple_submit_for_app_review.py` - post-upload gates.

## 4. What the API key does NOT unlock (separate owner actions, in order)

- **A 1.0.15+30 rebuild + re-freeze.** The key does not sign. The only signed iOS
  App Store IPA is the stale `1.0.14+29` (sha `1f92c7e2...`); the live tree is
  `1.0.15+30` and `build/apple/exports/` has no iOS export. This needs the
  **Apple Distribution** signing identity back in the keychain (currently only
  `Apple Development` is present), then
  `tools/build_apple_release_candidates.sh`, then owner approval of
  `owner_signoff.json` for the new hashes, then confirm in ASC that nothing above
  build 29 has already been processed.
- **The export/encryption questionnaire + DSA trader verification** - answered
  in the ASC console by the owner (+ counsel for export classification).
- **Re-shot screenshots** from the current build.
- **Reconciling the live App Privacy answers in ASC**: remove Purchase History
  and add Product Interaction to match the corrected manifests (see
  `privacy_label_v3.md` Section 3) - a console action, not a key action.
- The five signing certificates are a **keychain** gap, not an API-key gap.

## 5. The honest bottom line

The API key alone cannot produce an upload today: there is no current signed
candidate to upload. The shortest real path is: **owner restores the Apple
Distribution signing identity** -> **owner creates + installs the ASC API key**
-> rebuild/re-freeze 1.0.15+30 -> approve the owner signoff -> probe -> preflight ->
upload -> submit. The API key is the second of the two owner credentials; signing
is the first.

Nothing in this run was uploaded, submitted, staged for upload, or re-signed; no
key or credential material was read, printed, or stored.