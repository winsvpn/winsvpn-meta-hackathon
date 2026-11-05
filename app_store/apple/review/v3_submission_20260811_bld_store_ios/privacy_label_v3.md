# Apple App Privacy Label - Winn v3 submission (corrected re-answers)

**Prepared by lane `bld_store_ios` on 2026-08-11.** Nothing was published to App
Store Connect. These answers are the corrected truth for the next submission and
supersede the 2026-08-10 privacy-label drafts on two points: **Purchase History
is removed** and **Product Interaction is added** (see Section 3). Every claim below
was re-measured this run off the live tree. Re-reconciled on 2026-08-25 to the
four-type source position: Coarse Location, Device ID, User ID, and Product
Interaction, with Purchase History absent.

**Gate carried through everything:** as of 2026-08-11 no signed Apple release
build carries the winn3 datapath (the only signed iOS App Store IPA is the stale
`1.0.14+29`; `build/apple/exports/` contains only `macos-app-store-local/`, no
iOS export). The v3 sentences in Section 6 are **ready-to-enable blocks, not live
claims**; they unlock only against the exact submitted binary.

---

## 1. The privacy answers (what the label will say)

- **Data Used to Track You:** No.
- **Tracking domains:** none (`NSPrivacyTracking = false`,
  `NSPrivacyTrackingDomains = []` on every manifest).
- **Data linked to the user (4 types, all App Functionality, linked, not
  tracking). Purchase History dropped; Product Interaction added to source on
  2026-08-24):**
  - **Coarse Location** - IP-derived country/region/lat/lon used to centre the
    disconnected map. Read from Cloudflare's coarse network-metadata endpoint
    (first-party Win's VPN edge as less-specific fallback); Apple supplies map
    tiles via MapKit. The app never requests Apple's Location Services
    permission and does not retain returned IP/city/postal-code fields.
  - **Device ID** - install ID (24 random bytes,
    `SecRandomCopyBytes`), app info (model, platform, app version, locale,
    selected location, build capability flags), and a long-lived device public
    key (private key never leaves the device). Used for activation,
    configuration renewal, the three-device limit, abuse prevention, support.
  - **User ID** - account number, free-access account state,
    referral/account identity, server-side account association.
  - **Product Interaction** - selected VPN location, stealth mode, and Double
    VPN choices sent together with persistent account and device identifiers.
    Added as a source-declared type on 2026-08-24; the live App Store Connect
    answers still omit it and must add it at the next submission.
- **Data NOT collected:** Contact info, Health & Fitness, Financial info,
  Precise Location, Contacts, User Content, Browsing History, Search History,
  Sensitive Info, **Purchase History**, diagnostics uploaded by the app, DNS
  query contents, VPN traffic contents, destination activity logs, raw VPN
  flow metadata.

## 2. PacketTunnel extension

The extension receives tunnel configuration and status through the App Group
(`group.org.winsvpn.app`) and shared Keychain, then starts/stops the tunnel. Its
privacy manifest declares **no collected data**.

## 3. Purchase History removed / Product Interaction added (reconciled 2026-08-25)

The Apple app does **not** collect Purchase History: it embeds no payment SDK,
and the default Apple build opens no external purchase page. Each account's
paid-entitlement state, expiration and renewal status are reflected by the
service, not collected by the app. Product Interaction (selected VPN location,
stealth mode, Double VPN) is declared as linked, non-tracking App Functionality
data.

Re-measured this run against the live source with `plutil`: the source privacy
manifests are **already reconciled** to four types. `ios/Runner/PrivacyInfo.xcprivacy`
and `macos/Runner/PrivacyInfo.xcprivacy` each declare exactly four collected
types - `NSPrivacyCollectedDataTypeCoarseLocation`,
`NSPrivacyCollectedDataTypeDeviceID`,
`NSPrivacyCollectedDataTypeUserID`, and
`NSPrivacyCollectedDataTypeProductInteraction` - all linked, all App
Functionality, with no `NSPrivacyCollectedDataTypePurchaseHistory`.
`ios/PacketTunnel/PrivacyInfo.xcprivacy`, `macos/PacketTunnel/PrivacyInfo.xcprivacy`,
and the watch companion each declare none. Purchase History was removed from
source on 2026-08-23; Product Interaction was added to source on 2026-08-24. No
source privacy manifest edit remains.

The live App Store Connect answers were last synchronized 2026-07-11 and
**still carry Purchase History and omit Product Interaction**; nothing was
re-synced and nothing was published. **Owner action required at next
submission:** remove Purchase History and add Product Interaction to the App
Privacy answers in App Store Connect to match the manifests and this document.

## 4. Camouflage / calculator safety screen

The safety screen is a functional calculator; entering the user's configured
**six-digit PIN** (a legacy **four-digit** PIN from an older install is still
accepted at the decoy keypad) reveals the VPN interface. Leading-zero PINs are
supported (for example `028371`); a trivial all-zero or counting PIN is refused.
The PIN is verified against a salted PBKDF2
hash stored only in local app storage; PIN and digit-entry buffer are never
transmitted. This is a UX/camouflage feature, not a data-collection category.

## 5. Sources verified this run

| fact | measurement |
|---|---|
| in-tree version | `1.0.15+30` (`source/wins_vpn/pubspec.yaml:5`) |
| host manifests | 4 types: Coarse Location, Device ID, User ID, Product Interaction (Purchase History removed from source on 2026-08-23; Product Interaction added on 2026-08-24) |
| extension manifests | none via `plutil` |
| watch companion manifest | none via `plutil` |
| tracking flags | false / empty everywhere |
| longest-lived device marker | device public key (linkable, disclosed as Device ID) |
| no Location Services permission | source audit; map is IP-coordinate based |
| `WINS_ENABLE_EXTERNAL_PAYMENT_LINKS` | `defaultValue: false`, Apple build defaults to the store-safe premium-access notice; no external purchase link by default |

Companion evidence: `review/privacy_answers.md` (re-audited 2026-08-24, same
four-type position), `review/privacy_label_manifest.json`, and
`docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md`.

## 6. Gated v3 justification paragraph (enable only against the submitted binary)

> Win's VPN connects through its own first-party VPN protocol. Connection keys
> use X25519 ECDH combined with the NIST post-quantum key-exchange standard
> ML-KEM-768 (FIPS 203), and traffic is encrypted with ChaCha20-Poly1305 and a
> SHA-256 transcript hash. No third-party VPN engine processes user traffic on
> that path.

**Ready-to-enable ONLY IF** the submitted binary actually carries the winn3
datapath with suite `winn3-x25519-mlkem768-chacha20poly1305-sha256` (see
`export_compliance_v3.md`). Until then this paragraph stays out of the live
answers.