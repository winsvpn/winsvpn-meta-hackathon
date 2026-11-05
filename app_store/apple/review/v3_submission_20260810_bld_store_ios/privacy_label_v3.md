# Apple App Privacy (nutrition label) - v3 release answers

**Prepared by lane `bld_store_ios` on 2026-08-10. PREPARE ONLY - nothing
uploaded to App Store Connect, nothing submitted, no console touched.**

> **RECONCILED 2026-08-25 (superseded).** This 2026-08-10 privacy draft is
> stale. The authoritative position is `app_store/apple/review/privacy_answers.md`,
> `app_store/apple/review/privacy_label_manifest.json`, and the 2026-08-11
> packages. The source host manifests now declare EXACTLY FOUR types: **Coarse
> Location, Device ID, User ID, and Product Interaction** (all linked App
> Functionality, non-tracking). **Purchase History is NOT collected** and is not
> declared in any manifest. Winn v3 is primary; the Winn v1 fallback is AWG
> first, then Xray.

Source of truth verified this lane (not copied from a sibling):
- `ios/Runner/PrivacyInfo.xcprivacy` - parsed with `plutil`; declares exactly
  four collected-data types, each `NSPrivacyCollectedDataTypeLinked = true`,
  `NSPrivacyCollectedDataTypeTracking = false`, purpose
  `NSPrivacyCollectedDataTypePurposeAppFunctionality`; `NSPrivacyTracking = false`;
  empty `NSPrivacyTrackingDomains`.
- `ios/PacketTunnel/PrivacyInfo.xcprivacy` - parsed with `plutil`; **no
  collected-data entries** (`NSPrivacyCollectedDataTypes` empty).
- `app_store/apple/review/privacy_answers.md` (re-audited 2026-08-10).
- `app_store/apple/review/privacy_label_manifest.json`.

## The four declared data types (unchanged from published label)

All four: **App Functionality**, **linked to the user**, **not tracking**.

| Category | Data type | Purpose | Linked | Tracking |
|---|---|---|---|---|
| Location | Coarse Location | App Functionality | Yes | No |
| Identifiers | Device ID | App Functionality | Yes | No |
| Identifiers | User ID | App Functionality | Yes | No |
| Usage Data | Product Interaction | App Functionality | Yes | No |

### Supporting detail (each backed by a checked line)

- **Coarse Location** - IP-derived coordinates from `api.ipify.org` /
  Cloudflare coarse network metadata endpoint (first-party edge fallback) to
  center an Apple MapKit view; only country/region/lat/lon read; no Apple
  Location Services permission requested. (`privacy_answers.md` Section Coarse
  Location; verified `lib/approximate_location.dart` exists in-tree.)
- **Device ID** - 24 random bytes created on-device, Keychain
  `org.winsvpn.install-identity`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`;
  not a hardware id, not IDFV, not an advertising id. Second, same-type value:
  the long-lived cryptographic device public key, transmitted with every
  account verification/config renewal; used for provisioning, the three-device
  limit, abuse prevention; never tracking.
- **User ID** - account number, free-access state, referral identity.
- **Product Interaction** - selected VPN location, stealth mode, and Double VPN
  choices sent together with persistent account and device identifiers; linked
  App Functionality, not tracking. (Replaces the Purchase History row below.)
- **Purchase History** - **NOT collected.** This row is superseded: the app
  embeds no payment SDK and opens no external purchase page by default, and no
  manifest declares Purchase History. Paid-entitlement state is server-side
  account status, which is not Apple's Purchase History category.
- **PacketTunnel extension: declared empty.** App Group + shared Keychain carry
  config/status only (manifest verified empty via `plutil`).

## Data NOT collected (matches published claims)

Contacts, health/fitness, financial info, precise location, user content,
browsing history, search history, sensitive info, auto-uploaded diagnostics,
and - load-bearing for a VPN - no DNS query contents, traffic contents,
destination activity logs, or raw VPN flow metadata.

## v3 justification paragraph - paste into `privacy_answers.md` ONLY at ship time

Per `STORE_LISTING_V3_FIELD_DELTA_AUDIT` Section 1 and the release-copy draft: the four
answers and `privacy_label_manifest.json` entries do not change at v3. When the
**exact submitted binary** is verified to run the winn3 datapath, add this block
to the backing document (do NOT add a data type):

```text
## Winn Protocol v3 (standalone)
On builds where the Winn Protocol v3 datapath is active, tunnel traffic is protected
by the app's own first-party protocol using standard modern cryptography (X25519,
NIST ML-KEM-768, ChaCha20-Poly1305). No third-party VPN engine processes user traffic
on that path. Per-session protocol material (demux tokens, admission tags, handshake
and epoch keys) is ephemeral, is cleared at disconnect, and is not transmitted to
Win's VPN or any third party. This does not add any category to the data types above:
VPN traffic contents, DNS query contents, and destination activity remain uncollected.
```

**Gate:** no signed iOS release build currently carries v3 (verified this lane:
the only signed iOS App Store IPA under the repo is the stale `1.0.14+29`
candidate; in-tree version is `1.0.15+30`). Until the submitted binary carries
v3, keep this paragraph un-pasted.

## Manifest bookkeeping for the v3 submission

1. `privacy_label_manifest.json`: bump `app_version` to `1.0.15`,
   `build_number` to `30` (matches `pubspec.yaml:5` `1.0.15+30`), refresh
   `last_reviewed`.
2. Re-verify live sync to App Store Connect (`verified_at_utc` is stale
   2026-07-11) - an ASC/owner action.
3. v3 introduces no new extension or privacy manifest (protocol is in-process),
   so the collected-data entries are unchanged.

## Truth note (why this file is not a verbatim copy)

A sibling lane (`fin_store_ios`) produced a nearly identical privacy block.
This lane re-verified every claim against the `plutil` output of both privacy
manifests and the source documents rather than inheriting them. The four types,
their linkage and their purposes match the live manifests byte-for-byte in the
parts that matter; where prose elsewhere drifts (see the PIN-length note in
`review_notes_v3_ios.md`), this lane does not repeat it.