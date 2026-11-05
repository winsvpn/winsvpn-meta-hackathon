# Apple App Privacy Label - Winn v3 submission (fin_store_ios, 2026-08-11)

**Prepared by lane `fin_store_ios` on 2026-08-11. PREPARE ONLY - nothing was
published to App Store Connect.** Every fact below was re-measured this run off
the live tree, not copied from a prior document.

**Gate carried through everything:** no signed Apple App Store release carries
the winn3 datapath as of 2026-08-11. `build/apple/exports/` contains only
`macos-app-store-local/`; there is **no iOS export** and hence no current signed
v3 iOS build. The only signed iOS App Store IPA is the stale `1.0.14+29`. The
v3 sentences in Section 5 are **ready-to-enable blocks, not live claims**.

---

## 1. What the nutrition label will say

- **Data Used to Track You:** No.
- **Tracking domains:** none (`NSPrivacyTracking = false`,
  `NSPrivacyTrackingDomains = []` on every manifest).
- **Data linked to the user (corrected to 4 types, all App Functionality,
  linked, not tracking). Purchase History dropped; Product Interaction added
  to source on 2026-08-24):**
  - **Coarse Location** - IP-derived country/region/lat/lon used to centre the
    disconnected map. Read from Cloudflare's coarse network-metadata endpoint
    (first-party Win's VPN edge as less-specific fallback); Apple supplies map
    tiles via MapKit. The app never requests Apple's Location Services
    permission and does not retain the returned IP/city/postal-code fields.
  - **Device ID** - install ID (24 random bytes, `SecRandomCopyBytes`), app
    info (model, platform, app version, locale, selected location, build
    capability flags), and a long-lived device public key (private key never
    leaves the device). Used for activation, configuration renewal, the
    three-device limit, abuse prevention, support.
  - **User ID** - account number, free-access account state,
    referral/account identity, server-side account association.
  - **Product Interaction** - selected VPN location, stealth mode, and Double
    VPN choices sent together with persistent account and device identifiers.
    Added as a source-declared type on 2026-08-24; the live App Store Connect
    answers still omit it and must add it at the next submission.
- **Data NOT collected:** Contact info, Health & Fitness, Financial info,
  Precise Location, Contacts, User Content, Browsing History, Search History,
  Sensitive Info, diagnostics uploaded by the app, DNS query contents, VPN
  traffic contents, destination activity logs, raw VPN flow metadata. **Purchase
  History is not collected** (see Section 3).

## 2. PacketTunnel extension

The extension receives tunnel configuration and status through the App Group
(`group.org.winsvpn.app`) and shared Keychain, then starts/stops the tunnel.
Its privacy manifest declares **no collected data**.

## 3. Purchase History / Product Interaction - reconciliation status (READ first)

Re-measured on 2026-08-25 against the live source with `plutil`. The source
privacy manifests have **already been reconciled**; the only remaining mismatch
is the live App Store Connect answers, which have **not** been re-synced.

- **The decision (in the documents):** drop Purchase History and declare Product
  Interaction. The corrected position is that the Apple app does not collect
  Purchase History - it embeds no payment SDK and, by default, opens no
  external purchase page; each account's paid-entitlement/expiration/renewal
  state is reflected by the service, not collected by the app. Product
  Interaction (selected VPN location, stealth mode, Double VPN) is declared as
  linked, non-tracking App Functionality data. This is recorded in
  `privacy_answers.md` and `privacy_label_manifest.json`.
- **What is actually on disk (measured, `plutil`):**
  - `ios/Runner/PrivacyInfo.xcprivacy` - **4** collected types: Coarse Location,
    Device ID, User ID, and `NSPrivacyCollectedDataTypeProductInteraction`. No
    `NSPrivacyCollectedDataTypePurchaseHistory`.
  - `macos/Runner/PrivacyInfo.xcprivacy` - **4** collected types: Coarse
    Location, Device ID, User ID, and
    `NSPrivacyCollectedDataTypeProductInteraction`. No Purchase History.
  - `ios/PacketTunnel/PrivacyInfo.xcprivacy`,
    `macos/PacketTunnel/PrivacyInfo.xcprivacy` - 0 collected types each.
  - Purchase History was removed from source on 2026-08-23; Product Interaction
    was added to source on 2026-08-24. The on-disk Runner manifests therefore
    already match the corrected label exactly (4 types). No source privacy
    manifest edit remains.
- **What is still stale:** the live App Store Connect answers (last synced
  2026-07-11) still list Purchase History and omit Product Interaction. The
  source-side reconciliation is done; the live answers have **not** been
  re-synced and must be corrected at the next submission. That is an
  **owner/ASC console action**, not something the submission package does
  itself.

Honest position: "corrected-submission answers are 4 declared types (Coarse
Location, Device ID, User ID, Product Interaction) and the source manifests now
match; the live App Store Connect answers are stale (Purchase History present,
Product Interaction absent) until the owner re-syncs them." Do not upload a
build quoting 4 types while the live ASC answers still list a stale label, or
the reverse.

## 4. Calculator / camouflage safety screen

A functional calculator; entering the configured **six-digit PIN** (a legacy
**four-digit** PIN from an older install is still accepted at the decoy keypad)
reveals the VPN interface. Leading-zero PINs are supported (e.g. `028371`);
a trivial all-zero or counting PIN is refused. The PIN is verified against a
salted PBKDF2 hash stored only in local app storage;
PIN and digit-entry buffer are never transmitted. This is a UX/camouflage
feature, not a data-collection category.

## 5. Gated v3 justification paragraph (enable only against the submitted binary)

> Win's VPN connects through its own first-party VPN protocol. Connection keys
> use X25519 ECDH combined with the NIST post-quantum key-exchange standard
> ML-KEM-768 (FIPS 203), and traffic is encrypted with ChaCha20-Poly1305 and a
> SHA-256 transcript hash. No third-party VPN engine processes user traffic on
> that path.

This paragraph adds **no** data type and changes none of the four disclosures.
**Enable it only when the exact submitted binary carries the winn3 datapath**
(suite `winn3-x25519-mlkem768-chacha20poly1305-sha256` - see
`export_compliance_v3.md`). Until a signed v3 build exists it stays out of the
live answers.

## 6. Sources measured this run

| fact | measurement |
|---|---|
| in-tree version | `1.0.15+30` (`pubspec.yaml`) |
| host Runner manifests | 4 types: Coarse Location, Device ID, User ID, Product Interaction (Purchase History removed from source on 2026-08-23; Product Interaction added to source on 2026-08-24) |
| extension manifests | 0 collected types via `plutil` |
| tracking flags | false / empty everywhere |
| `ITSAppUsesNonExemptEncryption` | absent, Runner and PacketTunnel |
| longest-lived device marker | device public key (linkable, disclosed as Device ID) |