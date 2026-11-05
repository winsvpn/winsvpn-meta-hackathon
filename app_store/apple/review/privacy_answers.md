# Apple App Privacy Answers

Last reviewed: 2026-08-31

Status: OWNER APPROVED; COUNSEL REVIEW PENDING. This does not state or imply that counsel reviewed these answers. No App Store Connect change was made.

Live App Store Connect synchronization last verified at `2026-07-11T03:15:05Z`
for Apple ID `6789417002`. The published disclosure contains exactly Coarse
Location, User ID, Device ID, and Purchase History. Each type is used only for
App Functionality, is linked to the user's identity, and is not used for
tracking. App Store Connect shows no unfinished data-type setup banner.
This file does not claim App Store Connect was updated after that verification.

This draft was re-audited on 2026-08-24 against `lib/main.dart` to enumerate
every third-party network endpoint by name, to describe the long-lived
device public key honestly, and to classify selected VPN location, stealth
mode, and Double VPN choices under Apple's Product Interaction data type from
https://developer.apple.com/app-store/app-privacy-details/; it has **not**
been re-synchronized to App Store Connect. Before any submission, re-verify
the live answers against the final binary and this document.

On 2026-08-11 the Apple purchase-history declaration was reconciled out of the
source privacy manifests (`ios/Runner/PrivacyInfo.xcprivacy` and
`macos/Runner/PrivacyInfo.xcprivacy`) and out of this draft: the Apple app does
not collect Purchase History, because it embeds no payment SDK, offers no
in-app purchase and opens no checkout or payment page (its Premium Access Info
button opens only the developer's home page, https://www.winsvpn.org, in the
user's browser), and each account's paid-entitlement state is reflected by the
service rather than collected by the app. The live App Store
Connect answers still carry Purchase History and have **not** been re-synced
for this change (nothing was published). The next submission must remove
Purchase History from the App Privacy answers to match the manifests.

On 2026-08-24 the source privacy manifests and this draft declare Product
Interaction as linked to the user, not used for tracking, purpose App
Functionality, covering selected VPN location, stealth mode, and Double VPN
choices sent with persistent account and device identifiers. The live App
Store Connect answers still omit Product Interaction and have **not** been
re-synced for this change (nothing was published). The next submission must
add Product Interaction to the App Privacy answers to match the manifests.

Use this with `docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md` and the generated archive
privacy inventory in `build/apple/privacy/archive-privacy-manifests.md`.

## URLs

- Privacy Policy URL: `https://www.winsvpn.org/privacy/`
- Privacy Choices URL: `https://www.winsvpn.org/support/`
- Support URL: `https://www.winsvpn.org/support/`
- Marketing URL: `https://www.winsvpn.org/`

## Tracking

- Data Used to Track You: No.
- Tracking domains: none.

## Data Linked To The User

- Identifiers: User ID.
  - Covers account number, free-access account state, referral/account identity,
    and server-side account association.
- Identifiers: Device ID.
  - Covers install ID, device fingerprint, and device-bound access or
    abuse-prevention controls.
  - The activation, free-access, and configuration-renewal payloads also
    transmit app information for the same app-functionality purpose: the device
    model, platform, app version, locale, and build capability flags. These are
    transmitted to Win's VPN on activation and on configuration renewal and are
    used for compatibility, tunnel configuration, support, security, abuse
    prevention, and reliability. They are reported here as part of Device ID /
    app information rather than a separate category.
  - The app also generates a long-lived cryptographic key pair on first use of
    each account and transmits the derived public key to Win's VPN with every
    account verification and configuration renewal, not only at activation.
    That public key is a persistent, linkable device identity: it is stable
    across relaunches and reconnects, so it functions as a repeatable marker of
    the device rather than a one-time token. The private key never leaves the
    device; only the derived public key is transmitted. The key is used for
    connection provisioning, the three-device limit, and abuse prevention. It
    is not derived from hardware identifiers, not an advertising identifier,
    and never used for tracking. It is stored in the app's private storage or
    the platform keychain and is deleted or overwritten when the device is
    deactivated, replaced, or no longer needed.
  - The install ID is 24 random bytes generated on the device on first run
    (`SecRandomCopyBytes` on Apple platforms, `Random.secure()` elsewhere) and
    stored in the Keychain under `org.winsvpn.install-identity` with
    `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` on iOS. It is not a
    hardware identifier, not an advertising identifier, and not
    `identifierForVendor`. Because it lives in the Keychain it can survive a
    reinstall on the same device. The same kind of locally generated identifier
    is used on every platform, including Android, where it lives in the app's
    private storage instead and a reinstall produces a new value.
- Usage Data: Product Interaction.
  - Linked to the user. Not used for tracking. Purpose: App Functionality.
  - Covers selected VPN location, stealth mode, and Double VPN choices sent
    with persistent account and device identifiers.
  - The host Flutter app in `lib/main.dart` transmits `location` from
    `_requestedLocationSlug()`, `stealth_mode`, and `double_vpn_enabled` on paid
    activation (`_loginWithAccountNumber`), free-access login
    (`_freeAccessPayload`), and configuration renewal
    (`_refreshVpnConfigForCurrentSelection`). Those fields leave the device
    together with `account_number` and/or `device_id`.
  - Apple's App Privacy Details taxonomy defines Product Interaction as
    information about how the user interacts with the app:
    https://developer.apple.com/app-store/app-privacy-details/
  - Selected VPN location is a user product choice, not Coarse Location and
    not Device ID. Coarse Location remains the IP-derived map-center hint
    described below.
- Coarse Location: linked to the user for app functionality.
  - Only after the user asks to show the approximate-location map, the
    disconnected app first asks the compiled first-party Win's VPN origins and
    gateways for the IP-derived map scene. If those do not return specific
    coordinates or a region, it asks Cloudflare's coarse network metadata
    endpoint as the final fallback. This lookup is not automatic at launch.
  - On iOS and macOS, the coordinates center a standard Apple MapKit view and
    Apple supplies the map tiles. Other platforms use a labeled
    OpenStreetMap-derived tile layer through the first-party Win's VPN map
    endpoint, with the bundled public-domain Natural Earth raster retained only
    as the offline fail-closed fallback until a valid coarse coordinate pair
    and the first-party tile service are available.
  - The app reads only the coarse country, region, latitude, and longitude
    fields needed to center the map. It does not retain the endpoint's IP,
    city, or postal-code fields. This data is not used for tracking,
    advertising, analytics, or server selection, and the app does not request
    Apple's Location Services permission.
  - Separately, while the app is disconnected and after the user accepts the
    bundled Privacy Policy, it may query the third-party service
    `api.ipify.org` to display the device's current public IP address. That
    service receives the connection IP and ordinary request metadata; no other
    app data is sent, and the request is not made while a VPN tunnel is active.
  - After the user accepts the bundled Privacy Policy and only when the
    compiled gateways have actually failed (observed censorship), the app may
    fetch a small gateway-recovery record hosted on GitHub at
    `raw.githubusercontent.com` so it can still find a reachable gateway when
    the usual DNS or CDN paths are censored. GitHub receives the connection
    IP and ordinary request metadata. No account number, device identifier,
    or other user data is sent, and the record can only select among
    gateways already compiled into the signed build (see master legal
    document 2026-08-31.v4 section 5.7 and `lib/recovery_beacon_gate.dart`).
  - When the user runs the in-app speed test, the app measures throughput
    against the third-party hosts `speed.cloudflare.com` and
    `cachefly.cachefly.net`, and for western-US nodes additionally against
    `losangeles.ca.speedtest.frontier.com`,
    `lsanca-speedtest-ookla-02.st.charter.com`, and
    `speedtest.lax2.sonic.net`. Each server receives the connection IP and the
    transferred measurement traffic; no account number, device identifier, or
    other app data is included. These requests occur only while the user is
    running the speed test.

## Data Not Collected By Current Apple Code

- Contact info.
- Health and fitness.
- Financial info.
- Precise location.
- Contacts.
- User content.
- Browsing history.
- Search history.
- Sensitive info.
- Purchase History: **not collected by the Apple app.** Each account's paid-entitlement state, expiration, and
  renewal status are reflected by the service; the app does not receive the
  user's purchase history. The Apple build's Premium Access Info button opens
  the developer's home page, https://www.winsvpn.org, in the user's browser;
  the app embeds no payment SDK, offers no in-app purchase, and does not open a
  checkout or payment page. Purchase History is
  declared in no Apple privacy manifest for this app, so the App Privacy
  answers must not list it. At the next submission, the stale live App Store Connect Purchase History declaration must be removed.
  This file does not claim App Store Connect was updated.
- Diagnostics automatically uploaded from the app.
- DNS query contents, VPN traffic contents, destination activity logs, or raw
  VPN flow metadata.

## Calculator Safety Screen And Local Settings

- Fresh enrollment requires a six-digit PIN. Repeated digits, counting
  sequences, and repeating patterns are refused. Leading-zero PINs that are
  not trivially guessable are accepted. Do not instruct reviewers to use a
  trivial all-zero or counting PIN; use the six-digit PIN the reviewer set.
- A fresh install enrolls a six-digit PIN.
- The iOS app and the embedded watchOS companion use the device-visible name
  Win's VPN. The watch companion is a non-VPN remote for the iPhone and
  collects no App Privacy data.
- The PIN verifier is stored locally as a salted PBKDF2 hash. The PIN and its
  digit-entry buffer are not sent to Win's VPN or any third party.
- A later signed-device QA lane may preserve and restore the existing PIN,
  settings, cached node data, client keypair, and VPN configuration after its
  automated tunnel test. That process does not add a data-collection category
  or a device permission, and it is not a current 1.0.17+34 runtime receipt.
- The smaller blue map marker is only a visual presentation of the already
  disclosed rounded, IP-derived Coarse Location. It does not use Apple's
  Location Services and does not change the privacy-label answers.

## PacketTunnel Extension

The PacketTunnel extension receives tunnel configuration and status through the
App Group and shared Keychain, then starts or stops the tunnel. The extension's
privacy manifests declare no collected data. PacketTunnel and the embedded
non-VPN watch companion do not transmit selected VPN location, stealth mode, or
Double VPN; those fields leave the device only from the host Flutter app
payloads in `lib/main.dart`. The watch companion does not run Network
Extension and cannot approve the iOS VPN permission prompt.
