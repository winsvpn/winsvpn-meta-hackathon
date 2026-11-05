# Owner API-key report - App Store submission for Win's VPN

**Lane `bld_store_ios`, 2026-08-10. Prepared only; nothing submitted.**

## What the owner MUST generate and install (only the owner can)

An **App Store Connect API Key** is required to run every read-only live tool,
the upload, and the submit-for-review tool. It is **separate** from the five
signing certificates (signing is a keychain gap, not an API-key gap). The app
record exists under Apple ID **6789417002**, bundle `org.winsvpn.app`.

1. **Create:** appstoreconnect.apple.com -> Users and Access -> Integrations ->
   **App Store Connect API -> Generate API Key**. Name it `wins-release-upload`,
   role **App Manager** (App Manager or Admin is sufficient for uploads). Copy
   the **Key ID** (10 chars) and **Issuer ID** (UUID) now; download the `.p8`
   (shown once).
2. **Install private, outside the repo**, e.g.:
   `mkdir -p "/Users/owner/Library/Application Support/WinsVPN/asc"`,
   `chmod 700` the directory, place `AuthKey_<KEY_ID>.p8` there, `chmod 600`
   it. The tools require (verified in
   `tools/apple_app_store_connect_auth_probe.py:81-102`):
   - the key file is a **regular file** (not a symlink), lives **outside the
     project tree**, is owned by the current user, and has **owner-only
     permissions** unless you choose a different install path;
   - the basename of the key file must equal `AuthKey_<KEY_ID>.p8`.
3. **Supply** exactly three env vars to the tool session (never commit them):
   - `WINS_APPLE_AUTHENTICATION_KEY_PATH`
   - `WINS_APPLE_AUTHENTICATION_KEY_ID`
   - `WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID`

## Which tools unlock, in order (read-only -> destructive/subscription)

Verified this lane that each tool gates on the same three env vars:

| Tool | Needs key | Action |
|---|---|---|
| `tools/apple_app_store_connect_auth_probe.py` | yes | live auth probe (expects Apple ID 6789417002) |
| `tools/apple_app_store_connect_release_status.py` | yes | read-only live audit |
| `tools/apple_upload_exact_release_candidates.py --preflight` | yes | guarded hash-pinned preflight |
| `tools/apple_upload_exact_release_candidates.py --upload` | yes | the actual upload of NEW frozen candidates (none exist yet) |
| `tools/apple_upload_exact_screenshots.py --upload` | yes | uploads re-shot screenshots (existing set superseded) |
| `tools/apple_attach_processed_builds.py` | yes | attach processed builds |
| `tools/apple_set_all_storefront_availability.py` | yes | all storefronts |
| `tools/apple_submit_for_app_review.py` | yes | submit for App Review |

## Owner items NOT unblocked by an API key (separate actions)

1. Rebuild + re-freeze the iOS/macOS candidate pair at `1.0.15+30` (current
   in-tree version; only a stale `1.0.14+29` IPA exists and it is superseded),
   then approve `owner_signoff.json` for the new hashes.
2. Restore the **Apple Distribution signing identity** - only
   `Apple Development:` is in the keychain.
3. Answer the **export/encryption questionnaire + DSA/trader verification** in
   the ASC console (the export questionnaire surface appears because
   `ITSAppUsesNonExemptEncryption` is absent, which is intentional).
4. Re-shoot screenshots from the current build.
5. Re-verify live sync of the App Privacy label answers (last verified
   2026-07-11).

## What was NOT touched

No upload, no submit, no credential read/printed/stored, no console touched.
This lane wrote only new files under
`app_store/apple/review/v3_submission_20260810_bld_store_ios/` and this
handoff. See `APP_STORE_V3_SUBMISSION_PREP_20260810_fin_store_ios.md` for the
sibling lane's package (same four documents, prepared independently).