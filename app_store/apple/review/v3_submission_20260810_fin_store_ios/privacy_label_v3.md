# Apple App Privacy (nutrition label) - v3 release, ready to enter

**Prepared by lane `fin_store_ios` on 2026-08-10. PREPARE ONLY - nothing was
uploaded to App Store Connect.**

> **RECONCILED 2026-08-25 (superseded).** This 2026-08-10 privacy draft is
> stale and must not be used. The authoritative position is the live
> `app_store/apple/review/privacy_answers.md`,
> `app_store/apple/review/privacy_label_manifest.json`, and the 2026-08-11
> packages. Corrections:
> 1. The source host manifests now declare EXACTLY FOUR types, all linked App
>    Functionality, non-tracking: **Coarse Location, Device ID, User ID, and
>    Product Interaction**. Product Interaction covers selected VPN location,
>    stealth mode, and Double VPN choices.
> 2. **Purchase History is NOT collected** and is not declared in any manifest.
>    The table and the "four declared data types" list below that name Purchase
>    History are wrong and are superseded by the 2026-08-11 draft.
> 3. Winn v3 is primary; the Winn v1 fallback is AWG first, then Xray. The
>    "no third-party VPN engine processes user traffic" line is true only on the
>    v3 primary path.

Source of truth for the answers: `app_store/apple/review/privacy_answers.md`
(re-audited 2026-08-24 against `lib/main.dart`), the five `PrivacyInfo.xcprivacy`
manifests, and `privacy_label_manifest.json`. The declared types are the four
linked App Functionality types named above; they have NOT been re-synchronized
to App Store Connect (the live portal still carries Purchase History and omits
Product Interaction).

## The four declared data types (unchanged)

All four: **App Functionality**, **linked to the user**, **not tracking**.

| Category | Data type | Purpose | Linked | Tracking |
|---|---|---|---|---|
| Location | Coarse Location | App Functionality | Yes | No |
| Identifiers | Device ID | App Functionality | Yes | No |
| Identifiers | User ID | App Functionality | Yes | No |
| Purchases | Purchase History | App Functionality | Yes | No |

Details that support the answers (from `privacy_answers.md` 2026-08-10):

- **Coarse Location** - IP-derived coordinates from Cloudflare's coarse network
  metadata endpoint (first-party Win's VPN edge as less-specific fallback) to
  center an Apple MapKit view; reads only country/region/lat/lon, retains no
  IP/city/postal fields, never requests Apple Location Services permission.
- **Device ID** - 24 random bytes generated on-device (SecRandomCopyBytes on
  Apple), stored in Keychain under `org.winsvpn.install-identity` with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; NOT a hardware id, NOT
  identifierForVendor, NOT an advertising id.
- **Device ID (additional, same data type)** - the app's long-lived cryptographic
  public key, generated on first account use and transmitted with every account
  verification and configuration renewal. Persistent and linkable across
  relaunches (a device marker, not a one-time token); used for provisioning, the
  three-device limit, and abuse prevention; never an advertising id, never used
  for tracking; stored in app private storage or platform keychain, deleted when
  the device is deactivated.
- **User ID** - account number, free-access account state, referral/account
  identity, server-side account association.
- **Purchase History** - paid-entitlement state, account expiration, renewal
  status, referral credit. No payment SDK embedded; no external purchase website
  by default.
- **PacketTunnel extension: no collected data.** Declared empty in its
  `PrivacyInfo.xcprivacy`; App Group + shared Keychain carry config/status only.

## What is NOT collected (data-not-collected lines, as `privacy_answers.md`)

Contacts, health/fitness, financial info, precise location, user content,
browsing history, search history, sensitive info, diagnostics auto-upload,
and - load-bearing for a VPN - no DNS query contents, traffic contents,
destination activity logs, or raw VPN flow metadata.

## v3 justification paragraph - ADD to `privacy_answers.md` when v3 ships

Per `RELEASE_COPY_WINN3_DRAFT_20260810.md` Section 5.2 and the field-delta audit
(`STORE_LISTING_V3_FIELD_DELTA_AUDIT`) Section 1 row 13: the four answers and
`privacy_label_manifest.json` **do not change**. Only add this section to the
backing document (the ASC answers themselves are unplugged from this paragraph  -
do not add a data type):

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

**Gate:** paste into `privacy_answers.md` (and re-run the submission-package
validator) only when the **exact submitted binary** carries the winn3 datapath  -
per the E2E matrix, no signed release build carries v3 on any of the five
platforms as of 2026-08-10, so today this stays a ready-to-enable block.

## What needs to be updated for the v3 submission

1. `privacy_label_manifest.json` - bump `app_version` 1.0.14->1.0.15 and
   `build_number` 29->30 to match `pubspec.yaml` (in-tree `1.0.15+30`), and raise
   `last_reviewed` to the release date. The collected-data entries change in no
   other way.
2. Re-verify live-sync to App Store Connect (`verified_at_utc` is 2026-07-11;
   the answers were never re-synced). That is an ASC/owner action, not an on-disk
   one.
3. No new privacy manifest is introduced by v3 (no new extension; the protocol
   is in-process). Re-alphabet the episode-by-episode confirmation in the
   archive privacy inventory once a signed v3 archive exists.