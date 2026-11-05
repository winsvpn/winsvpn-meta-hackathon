# Apple App Privacy Label Audit

Last reviewed: 2026-08-31

Status: OWNER APPROVED; COUNSEL REVIEW PENDING. This does not state or imply
that counsel reviewed this draft. No App Store Connect change was made.

This file is the working App Store Connect privacy-label draft for the
Win's VPN iOS and macOS apps. Refresh it before every App Store submission and
whenever a new SDK, payment flow, analytics tool, support upload, or server-side
data flow is added.

Release `1.0.15+30` has two required Apple artifacts: one iOS App Store IPA that
embeds the non-VPN watchOS companion, and one macOS App Store PKG. tvOS is not
a privacy-label, export-compliance, signing, upload, or receipt surface for this
release. The watch companion discloses no collected data.

Official Apple references:

- https://developer.apple.com/app-store/app-privacy-details/
- https://developer.apple.com/app-store/review/guidelines/
- https://developer.apple.com/documentation/bundleresources/privacy-manifest-files
- https://developer.apple.com/documentation/bundleresources/describing-data-use-in-privacy-manifests

## Current Build Evidence

- No analytics, ads, or crash-reporting SDK is declared in `pubspec.yaml`.
- The iOS and macOS host privacy manifests disclose linked User ID, Device ID,
  Coarse Location, and Product Interaction collection for app functionality
  only. Purchase History is not collected by the Apple app.
- Product Interaction is linked to the user, not used for tracking, and used
  only for App Functionality. It covers selected VPN location, stealth mode,
  and Double VPN choices sent with persistent account and device identifiers
  from `lib/main.dart` (`location`, `stealth_mode`, `double_vpn_enabled` on
  `_loginWithAccountNumber`, `_freeAccessPayload`, and
  `_refreshVpnConfigForCurrentSelection`). Apple's App Privacy Details
  taxonomy classifies that as Product Interaction:
  https://developer.apple.com/app-store/app-privacy-details/
- The iOS WinsWatch companion privacy manifest discloses no collected data
  and no required-reason APIs.
- The iOS and macOS PacketTunnel privacy manifests disclose no collected data.
  PacketTunnel and the watch companion do not transmit selected VPN location,
  stealth mode, or Double VPN; those fields leave the device only from the
  host Flutter app control-plane payloads.
- On 2026-07-09, the post-Apple-premium-label signed export run with
  `WINS_APPLE_PRIVACY_ARCHIVE_REPORT=1` regenerated
  `build/apple/privacy/archive-privacy-manifests.json` and
  `build/apple/privacy/archive-privacy-manifests.md`; the latest evidence is
  `/tmp/wins_apple_signed_exports_after_apple_premium_label_20260709131620.log`.
  That run's iOS archive and macOS archive each contained exactly three privacy
  manifests: host app, PacketTunnel extension, and Flutter framework. All six
  of those manifests had tracking disabled and no tracking domains. No current
  1.0.15+30 archive exists. That
  inventory predates the 2026-08-24 Product Interaction source declaration,
  so it no longer satisfies the current four-type host gate and must be
  regenerated from fresh archives. It is not claimed as a rebuilt archive or
  an App Store Connect update.
- The archive privacy report lane now fails if archived products do not contain
  exactly one host-app manifest, exactly one PacketTunnel manifest, the exact
  expected framework manifest set, host collection equal to exactly User ID,
  Device ID, Coarse Location, and Product Interaction for app functionality
  only, no PacketTunnel data collection, no framework data collection, and no
  tracking domains.
- The app sends account and device setup metadata to the Win's VPN control hub:
  account number or free-access account state, install/device fingerprint,
  device model, platform, app version, locale, selected location, stealth
  mode, Double VPN, protocol choices, client public key, and legal-acceptance
  fields. Selected location, stealth mode, and Double VPN are Product
  Interaction, not Device ID and not Coarse Location.
- The app stores local settings in app storage or Apple Keychain, including
  install ID, client key material, selected server/protocol, legal acceptance,
  referral/account fields, and local VPN configuration state.
- Fresh enrollment requires a six-digit PIN and refuses repeated digits,
  counting sequences, and repeating patterns. Leading-zero PINs that are not
  trivially guessable are accepted; `000000` is not
  (`pinPolicyRejectionReason` and `isTriviallyGuessablePin`,
  `lib/local_security.dart`). Legacy four-digit PINs keep unlocking and are
  offered an in-app upgrade to six digits. Neither the PIN nor the digit-entry
  buffer is transmitted.
- Automated signed-device tunnel QA snapshots and restores the existing local
  PIN, settings, cached node data, client keypair, and VPN configuration. The
  release validator rejects a passing runtime result unless restoration is
  confirmed.
- Only after the user requests the map, the app asks the compiled first-party
  Win's VPN origins and gateways for IP-derived coordinates and a country/region
  hint, then uses Cloudflare's coarse network metadata endpoint only as the final
  fallback. This lookup is not automatic at launch. On Apple platforms these
  values center a standard MapKit view and Apple supplies the map tiles. The app
  reads only country, region, latitude, and longitude; it does not retain the
  endpoint's returned IP, city, or postal-code fields. It does not request
  Apple's Location Services permission or use the map data for tracking,
  advertising, analytics, or server selection.
- After privacy acceptance and only when the compiled gateways have actually
  failed, the app may fetch a small gateway-recovery record hosted on GitHub at
  `raw.githubusercontent.com` (master legal document 2026-08-31.v4 section 5.7;
  see `lib/recovery_beacon_gate.dart`). GitHub receives the connection IP and
  ordinary request metadata only; no account number, device identifier, or
  other user data is sent, and the record can only select among gateways
  already compiled into the signed build. This matches the third-party
  destination disclosure in `docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md`.
- The shared Flutter package includes `flutter_map` and `latlong2`. Non-Apple
  platforms fetch OpenStreetMap-derived tiles from the compiled first-party
  endpoint `https://www.winsvpn.org/api/site/map-tile/{z}/{x}/{y}.png`
  (`PublicIpMapBackdrop.defaultTileUrlTemplate`); release builds ignore the
  `WINS_MAP_TILE_URL` override and the tile-host allowlist is the first-party
  set (`trustedMapTileHosts` in `lib/pre_vpn_geo.dart`). No build requests tiles
  from an OpenStreetMap tile server. `openstreetmap.org` appears only as the
  license attribution link. The audited platform boundary routes iOS and macOS
  to native MapKit before any non-Apple tile validation or construction. This
  dormant cross-platform code is not a separate Apple data collection path.
- Rendering that coarse location with a smaller blue marker is a presentation
  change only. It does not add precise-location collection or a Location
  Services permission.
- The current Flutter app does not include an in-app payment SDK.
- Owner ruling 2026-10-24: The Apple build's Premium Access Info button opens the developer's home page, https://www.winsvpn.org, in the user's browser.
  The app embeds no payment SDK, offers no in-app purchase, and does not open a
  checkout or payment page. Users can use an existing Win's VPN account number
  or Try Free Server.
- The app and PacketTunnel extension are designed not to collect browsing
  history, DNS query contents, traffic contents, destination activity logs,
  contacts, health data, photos, or precise location.

## Recommended App Store Connect Answers

Data Used to Track You: No

Tracking domains: none.

Data Linked to the User:

- Identifiers: User ID. Use this for account number, free-access account state,
  referral/account identity, and server-side account association.
- Identifiers: Device ID. Use this for install ID, device fingerprint, and
  device-bound access or abuse-prevention controls.
- Usage Data: Product Interaction. Linked to the user, not used for tracking,
  purpose App Functionality. Use this for selected VPN location, stealth mode,
  and Double VPN choices sent with persistent account and device identifiers.
  Live App Store Connect still omits Product Interaction and must add it at
  the next submission. This file does not claim App Store Connect was updated.
- Coarse Location: linked to the user for app functionality. Use this for the
  IP-derived coordinates and country/region map center. Apple MapKit supplies
  standard map tiles on iOS and macOS; the bundled Natural Earth map remains a
  fallback on other platforms. The location hint is not used for tracking,
  advertising, analytics, or server selection.

Data Not Linked to the User:

- None currently proven for the Apple app. Do not claim anonymous or unlinked
  collection unless the final build and backend logs prove it.

Not collected by the current iOS/macOS app code:

- Contact info.
- Health and fitness.
- Financial info.
- Precise location.
- Contacts.
- User content.
- Browsing history.
- Search history.
- Sensitive info.
- Purchase History: not collected by the Apple app. Paid-entitlement, expiration, renewal, and referral-credit
  state is server-side account status, not Apple's Purchase History category.
  The current Apple build embeds no payment SDK and does not open an external
  purchase page by default. Live App Store Connect answers still list Purchase
  History and must be corrected. At the next submission, the stale live portal declaration must be removed.
  This file does not claim App Store Connect was updated.
- Diagnostics automatically uploaded from the app.

PacketTunnel extension: no separate data collection. The host app declares User
ID, Device ID, Coarse Location, and Product Interaction. The extension receives
tunnel configuration and status through the App Group and shared Keychain, then
starts or stops the tunnel. It should not log or upload raw destination, DNS, or
payload content. PacketTunnel and the watch companion do not transmit selected
VPN location, stealth mode, or Double VPN.

## Submission Checklist

- Run `WINS_PREFLIGHT_ONLY=1 WINS_APPLE_PRIVACY_ARCHIVE_REPORT=1
  WINS_REQUIRE_APPLE_ENGINE=1 bash tools/apple_runtime_smoke.sh` after local
  iOS and macOS archives exist, then review
  `build/apple/privacy/archive-privacy-manifests.json` and
  `build/apple/privacy/archive-privacy-manifests.md`.
- Treat a passing local archive privacy report as a pre-submission guard only;
  it does not replace the final Xcode/App Store Connect privacy report.
- Generate Xcode privacy report from the final iOS and macOS archives.
- Compare the generated privacy report against this audit and every
  `PrivacyInfo.xcprivacy` file.
- Confirm App Store Connect privacy labels match the final binary, website
  account flow, and backend retention behavior.
- Confirm Purchase History is not collected and is not disclosed as linked
  app-functionality data. Live App Store Connect still lists it and must be
  corrected at the next submission. The stale live portal declaration must be
  removed. Do not claim App Store Connect was updated.
- Confirm Product Interaction is disclosed as linked to the user, not used for
  tracking, purpose App Functionality, covering selected VPN location, stealth
  mode, and Double VPN choices sent with persistent account and device
  identifiers. Live App Store Connect still omits it and must add it at the
  next submission.
- Confirm Coarse Location remains disclosed as linked, non-tracking app-
  functionality data while the app uses the first-party IP-derived country/
  region hint to center its native MapKit view.
- Confirm the final Apple source audit still proves that the MapKit branch
  precedes all OpenStreetMap tile validation and construction, and that no
  source references a third-party OpenStreetMap tile server, only the compiled
  first-party tile endpoint and the OpenStreetMap attribution link
  (`lib/main.dart:787`).
- Confirm the Apple build's Premium Access Info button still opens only the
  developer's home page, https://www.winsvpn.org, and that the app still embeds
  no payment SDK, offers no in-app purchase, and opens no checkout or payment
  page.
- Recheck this file after any analytics, support upload, payment, referral,
  account, or diagnostic feature change.
