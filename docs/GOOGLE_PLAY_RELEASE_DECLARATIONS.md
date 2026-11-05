# Google Play Release Declarations

Prepared for the first Google Play release of Win's VPN.

## App Identity

- Package name: `org.winsvpn.app`
- App name: `Win's VPN`
- Upload certificate owner: `CN=Wins VPN Inc, O=Wins VPN Inc, C=US`
- Upload certificate SHA-256: `4E:BB:FF:15:A1:27:4E:7B:07:27:67:FA:37:F0:0E:8F:FB:EA:FA:B8:0C:B6:1B:51:A5:AB:59:8A:F6:DB:E6:EE`
- Core purpose: user-initiated VPN privacy, security, anti-censorship access, malicious-site filtering, and optional split tunneling.
- Tunnel protocol: Winn v3 is the product's primary protocol. Winn v1 AWG fallback is the compatibility path. The Android build ships and runs no Xray.

## Tunnel Protocol

Winn v3 is the product's primary protocol. Winn v1 AWG fallback is the
compatibility path after a served Winn v3 attempt. The Android build ships and
runs no Xray: `VpnTunnelService` refuses Xray mode, the client tells the hub
`supports_xray: false` on Android, and `libxray.so` is excluded from packaging.
Learned network-specific demotion cannot skip a served Winn v3 lead attempt and
cannot remove AWG.

## Payments

For the Google Play Android release build, the entry is labeled `Premium Access Info`. The Google Play build's Premium Access Info button opens the developer's home page, https://www.winsvpn.org, in the user's browser. The app embeds no payment SDK, uses no Google Play Billing, and does not open a checkout or payment page. Users can use an existing account or the free server.

Important: Google Play policy generally requires Play Billing for in-app digital VPN subscriptions unless an allowed alternative billing or outside-offers program applies. Before enabling paid subscriptions inside the Play-distributed app, integrate Play Billing purchase tokens with the control hub and verify purchases server-side.

## VpnService Declaration

Suggested Play Console text:

Win's VPN uses Android `VpnService` as the app's core user-facing function. The user taps the power button to start an encrypted VPN tunnel and can disconnect at any time from inside the app or from the persistent Android VPN notification. The service routes user-selected device traffic through Win's VPN servers for privacy, security, anti-censorship access, and malicious-site filtering. The tunnel uses Winn v3 as the product's primary protocol; Winn v1 AWG fallback is the compatibility path, and the Android build ships and runs no Xray. The app does not use `VpnService` to monetize traffic, inject ads, manipulate traffic for advertising, or collect browsing history, DNS query history, traffic contents, or destination activity.

If the form asks whether providing a VPN is the app's core functionality:

Yes. Win's VPN is a user-initiated VPN app. `VpnService` is required to create Android's secure device-level tunnel to a remote VPN endpoint, route selected device traffic through the tunnel, show Android's VPN indicator, and support user-controlled split tunneling. There is no non-VPN Android API that can provide this core function.

If the form asks what data the VPN service collects or shares:

No browsing history, DNS query history, traffic contents, or destination activity is collected or shared through `VpnService`. Limited operational metadata outside the VPN traffic path may be used for activation, account/device-limit enforcement, free access, legal acceptance, security, abuse prevention, and support, as disclosed in the privacy policy.

If the form asks about traffic monetization:

No. Win's VPN does not redirect or manipulate traffic from other apps for monetization, advertising, ad measurement, ad fraud, or profiling. The tunnel exists only to provide the user-requested VPN, security, anti-censorship, malicious-site filtering, and split-tunneling functionality.

Privacy policy URL for Play Console:

https://www.winsvpn.org/privacy/

Data retention / deletion note for the Data safety form:

Win's VPN does not collect or keep VPN activity logs. VPN traffic content, raw VPN traffic, browsing history, DNS query history, and destination activity are not collected. Transient connection/session state is cleared when the VPN disconnects. Device-limit metadata used to enforce the three-device limit is deleted or overwritten when the device is deactivated, replaced, or no longer needed for active account operation. App-collected operational data that is no longer needed is deleted or anonymized within 90 days, with narrow exceptions for active-account operation, payment, legal, security, fraud-prevention, dispute-resolution, and legal acceptance needs.

### Data Safety Matrix (match these answers exactly to the submitted build)

| Google Play data type | Collected | Shared | Required / optional | Processing and purpose |
|---|---:|---:|---|---|
| Device or other IDs (random per-install app identifier generated on device) | Yes | No | Required after the user accepts the bundled Privacy Policy and chooses to activate/free-connect | Transmitted to Win's VPN and linked to the account or free-access identity for app functionality, account management, the three-device limit, fraud prevention, security, and abuse prevention. The identifier is 24 random bytes from `Random.secure()`, written to the app's private storage on first run and regenerated on reinstall; it is **not** `Settings.Secure.ANDROID_ID`, not a hardware identifier, and not an advertising identifier. Not used for ads or tracking. Retained device-limit value is protected by the hub and deleted or overwritten when the device is deactivated, replaced, or no longer needed. |
| User IDs (account number or free-access identity) | Yes | No | Required to activate or use free access | Account authentication, account management, service delivery, device-limit enforcement, fraud prevention, security, and legal-acceptance evidence. |
| Email address | Yes, when provided for a paid/manual account or support | Shared only with SMTP2GO as a service provider | Optional in the Android app; may be required in an external purchase/support flow | Account provisioning, transactional service email, receipts, and support. Not used for ads or tracking. |
| Approximate location | Yes, transiently after consent | Map/hosting provider receives the requested region and request IP as a service provider | Optional map presentation; not device GPS | Coarse public-IP-derived country/region/city scene and a surrounding map. Win's VPN does not retain returned public IP, city, postal code, or map-view history. |
| Purchase history / payment confirmation metadata | Yes, when an external PayPal purchase provisions the account | PayPal is the payment processor | Optional; not collected for free access | Account provisioning, subscription/account status, receipts, accounting, fraud prevention, and disputes. Raw card numbers are never received or stored by Win's VPN. |
| App info (platform/app version, device model, locale, capability flags) | Yes | No | Required for activation/configuration | Compatibility, app functionality, tunnel configuration, support, security, abuse prevention, and reliability. |
| Diagnostics / crash information | Only when explicitly supplied by the platform or user; verify the Play SDK data-disclosure report before selecting this row | Only the platform/service provider involved | Optional | Troubleshooting, security, and reliability. The release must not claim automatic crash collection unless the final SDK report proves it. |
| Installed apps | No off-device collection | No | Optional local split-tunneling feature | The inventory is accessed only after a separate disclosure and stays on-device. Only user-selected package identifiers are stored locally and passed locally to Android `VpnService`. |
| Browsing history, DNS query history, traffic content, raw VPN traffic, destination activity | No | No | Not applicable | Not collected or retained. |

Before submission, export the final Play SDK Index/data-disclosure report and compare it to this matrix. Any SDK that collects additional categories invalidates these answers and must be removed or disclosed before publishing.

Third-party network destinations outside the tunnel (declare if the form asks
where the app connects before a VPN session):

- `raw.githubusercontent.com` - after the user accepts the bundled Privacy
  Policy, the app fetches a small gateway-recovery file so it can still find a
  reachable gateway when the usual DNS or CDN paths are censored. GitHub
  receives the connection IP and ordinary request metadata. No account number,
  device identifier, or other user data is sent, and the file can only select
  among gateways already compiled into the signed build.
- `api.ipify.org` - while the app is disconnected, it may query this third-party
  service so the connection-status UI can display the device's current public
  IP address. The service receives the connection IP and ordinary request
  metadata; no account number, device identifier, or other app data is sent,
  and the request is never made while a VPN tunnel is active.
- `speed.cloudflare.com/meta` (Cloudflare) and the first-party Win's VPN edge
  geo endpoint - before a VPN session and after the user accepts the bundled
  Privacy Policy, the app may retrieve a coarse public-IP location from
  Cloudflare's network-metadata endpoint or a first-party edge endpoint to
  center the pre-connect map. The endpoint that derives coarse location and the
  map provider receive the connection IP and ordinary request metadata; no
  account number, device identifier, or other user data is sent, and the app does
  not request device GPS for this feature.
- `speed.cloudflare.com` and `cachefly.cachefly.net` - when the user runs the
  in-app speed test, the app downloads and uploads measurement traffic to these
  third-party test servers. Each receives the connection IP, ordinary request
  metadata, and the transferred measurement traffic; no account number, device
  identifier, or other app data is included. These requests occur only while
  the speed test is running.
- `losangeles.ca.speedtest.frontier.com`,
  `lsanca-speedtest-ookla-02.st.charter.com`, and
  `speedtest.lax2.sonic.net` - additional third-party speed-test hosts used
  only for nodes in the western United States, with the same data profile as
  the hosts above.
- Win's VPN control plane - the hub throttles repeated failed attempts using
  short-lived counters and security-event records keyed to an HMAC-hashed form
  of the source IP, device identifier, or account number. The raw address is not
  retained. These records exist only for security, fraud prevention, abuse
  response, and device-limit enforcement.
  In addition to the random install identifier, every account verification and
  configuration renewal request transmits the app's long-lived device public
  key (`client_public_key`), which is stable across relaunches and reconnects
  and therefore acts as a persistent, linkable device marker. It is used for
  connection provisioning, the three-device limit, and abuse prevention; it is
  not derived from hardware or advertising identifiers and is not used for
  advertising or tracking. The account-side record is deleted or overwritten
  when the device is deactivated or replaced.

Reviewer demo steps:

1. Install and open Win's VPN.
2. Set a six-digit PIN. Fresh enrollment requires exactly six digits
   (`kCamouflagePinLength`). Repeated digits such as `000000`, counting
   sequences, and repeating patterns are refused at enrollment. Leading-zero
   PINs that are not trivially guessable are accepted. This build cannot enroll
   a four-digit PIN. A stored four-digit credential from an older install still
   unlocks the phone calculator if present.
3. Tap `Try Free Server (100 Mbps upload and download)`.
4. Review the legal notice.
5. Review the separate Android `VpnService` disclosure.
6. Check both acceptance boxes and tap `Agree`.
7. Approve the Android VPN permission prompt.
8. Confirm the Android VPN notification appears and the app shows `SECURED`.
9. Only after that successful connection, observe the optional Android battery
   optimization exemption sheet. Choosing Deny must not disconnect or block the
   VPN.
10. Tap the power button to disconnect and confirm the VPN notification disappears.

## Battery Optimization Exemption Declaration

Manifest permission:

- `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`

Suggested Play Console text:

Win's VPN requests a battery-optimization exemption only to protect its core,
user-initiated VPN function. Android Doze suspends ordinary network access while
the device is idle; applying that suspension to an already-active VPN can
interrupt the encrypted tunnel the user explicitly started. Win's VPN never
shows this request at app launch, during initialization or activation, before
privacy/legal acceptance, or before Android's VPN authorization. The first
request is eligible only after the tunnel passes native readiness and Internet
proof, remains active, and the app commits the connected state and runtime
settings. The request is optional: denial does not prevent or disconnect VPN
use.

Exact implementation and timing:

- Dart gates the request to Android, accepted privacy consent, separately stored
  acceptance of Android `VpnService` disclosure version `2026-07-20.v2`, a
  committed connected tunnel, and no prior check in the current app process.
  Legacy installs with a missing or stale
  `android_vpn_service_disclosure_consent_version` must accept the current
  disclosure before activation or a cached-config connection. The smart
  protocol path rechecks the version before its first AWG or Xray candidate.
- The call is scheduled only after `_saveVpnRuntimeSettings` completes and
  immediately before the successful tunnel candidate returns; neither direct
  AWG nor Xray fallback has a separate request site. Single and Double VPN use
  this same success boundary.
- Android native code independently rejects the request unless
  `VpnTunnelService.isTunnelHealthy()` is true.
- The app checks `PowerManager.isIgnoringBatteryOptimizations` first. It uses
  `Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` only when not already
  exempt and falls back to the general battery-optimization settings if the
  direct action is unavailable.
- A local timestamp is written before the system action and enforces a seven-day
  cooldown. The app evaluates the feature at most once per app process,
  including after a denial or unavailable system screen. The timestamp is not
  uploaded.

Reviewer steps:

1. Use a fresh install or clear the test app's local data and remove any existing
   battery exemption for `org.winsvpn.app`.
2. Open the app and remain on the privacy-consent screen. Confirm no battery
   exemption sheet appears.
3. Accept the bundled privacy/legal and Android `VpnService` disclosures, but do
   not connect yet. Confirm no battery exemption sheet appears.
4. Start the VPN and approve Android's VPN authorization. Wait until the
   persistent VPN notification is present and the app reports `SECURED`.
5. Confirm the battery exemption sheet can appear only now. Choose Deny and
   verify the active VPN remains connected.
6. Disconnect and reconnect during the same app process. Confirm the sheet does
   not repeat.
7. Restart and reconnect within seven days. Confirm the locally recorded
   cooldown prevents another sheet. A fresh-data review run resets this state.

Policy rationale references:

- Android Doze/App Standby guidance:
  https://developer.android.com/training/monitoring-device-state/doze-standby
- Google Play `VpnService` policy:
  https://support.google.com/googleplay/android-developer/answer/12564964

## Foreground Service Declaration

Manifest service:

- Class: `org.winsvpn.app.VpnTunnelService`
- Type: `specialUse`
- Permission: `android.permission.FOREGROUND_SERVICE_SPECIAL_USE`

Suggested Play Console text:

Win's VPN uses a foreground service only while the user-requested VPN tunnel is active. The foreground service keeps the encrypted tunnel process alive, maintains the user-visible VPN notification, and prevents Android from silently killing the tunnel during screen-off or network changes. Stopping the VPN from the app or notification tears down the tunnel and stops the foreground service.

User impact if deferred or interrupted:

If this foreground service is stopped while the VPN is connected, the user's encrypted route may drop unexpectedly and network traffic may return to the normal device route. The persistent notification is necessary so users always know when the VPN is active.

## QUERY_ALL_PACKAGES Declaration

Suggested Play Console text:

Win's VPN requests `QUERY_ALL_PACKAGES` only for the user-facing split tunneling feature named `Exclude Apps From VPN (Split Tunneling)`. Split tunneling requires showing the user a searchable list of installed apps, including system apps, so the user can choose which apps should be excluded from the VPN tunnel. Android's VPN API needs package names for `addDisallowedApplication(...)`; without broad package visibility, Win's VPN cannot reliably present all eligible apps for this core VPN interoperability feature. The phone and TV flavors of `org.winsvpn.app` both inherit this permission from `android/app/src/main/AndroidManifest.xml` and both expose that per-app picker. Wear OS does not request `QUERY_ALL_PACKAGES`.

Data handling:

Installed-app inventory is used locally on the device to render the split-tunneling picker. Win's VPN does not sell installed-app inventory, use it for ads or analytics monetization, or upload the full installed-app inventory to Win's VPN servers. Selected excluded package names are stored locally in the app settings and passed locally to Android `VpnService` so Android can exclude those apps from the tunnel.

The app does not enumerate installed apps at startup. When the user first opens `Exclude Apps From VPN (Split Tunneling)`, the app presents a separate installed-app access disclosure with `Not now` and `Continue` actions. Enumeration begins only after the user chooses `Continue`; `Not now` returns without accessing the inventory and does not prevent ordinary VPN use.

Reviewer demo steps:

1. Activate the app with a test/free account.
2. Expand `Exclude Apps From VPN (Split Tunneling)`. On Android TV, reach the
   same control with D-pad navigation.
3. Read the separate installed-app access disclosure and choose `Not now`; confirm the picker remains closed and normal VPN use remains available.
4. Expand `Exclude Apps From VPN (Split Tunneling)` again, then choose `Continue`.
5. Search for an app.
6. Select one app to exclude.
7. Confirm the summary changes to show the number of excluded apps.

Release gate: `QUERY_ALL_PACKAGES` is a Google Play sensitive-permission declaration, not a code defect, so its Play Console **Permissions Declaration Form** approval status is a publication gate rather than something a build or test can verify. Submit this declaration with the Play Console upload that first requests the permission. Do not promote that build to a public Play Store track until Play Console shows the declaration `Approved`. If Google instead returns `Rejected` or `Needs changes`, do not resubmit the same declaration; redesign or remove the all-apps picker (for example, an allowlist-only or system-app-excluded picker that avoids `QUERY_ALL_PACKAGES`) before the next submission attempt.

Approval status: `PENDING` - update this line to `APPROVED (YYYY-MM-DD)` once Play Console confirms it, and to `REJECTED` with the reviewer's stated reason if Google declines it. Treat this line as the single source of truth for whether the current build is allowed to ship with this permission, including the TV flavor of the same application ID.

## Camouflage / Calculator Mode Reviewer Note

Suggested Play Console note:

Win's VPN includes Android camouflage mode for user safety in high-risk censorship environments, including Burma/Myanmar, where visibly installed VPN apps can expose users to retaliation or device-search risk. This feature is disclosed in the legal acceptance text and is controlled by the user through their PIN. It does not hide malicious behavior, it does not remove the Android VPN permission prompt, and it does not remove the persistent Android VPN notification while the VPN tunnel is active. Calculator camouflage is phone-only; Android TV never presents the decoy calculator.

Reviewer access:

- Open the app normally as `Win's VPN`.
- Fresh enrollment uses the six-digit PIN contract (`kCamouflagePinLength` = 6).
  Repeated digits such as `000000`, counting sequences, and repeating patterns
  are refused at enrollment. Leading-zero PINs that are not trivially guessable
  are accepted.
- If the phone app is in calculator mode, enter the configured six-digit PIN to
  return to the VPN interface. A stored four-digit PIN from an older install
  still unlocks if present; this build cannot enroll a four-digit PIN.
- Do not instruct reviewers to use `0000` or `000000` as a review PIN.
  `000000` is refused at enrollment. Use the six-digit PIN the reviewer set
  during setup.
- Android TV never presents calculator camouflage. TV activation still uses the
  same six-digit enrollment PIN contract.

## Content Rating (IARC) Questionnaire

The Play Console content-rating questionnaire is shared by the phone/tablet,
TV, and Wear form factors of `org.winsvpn.app`. Answer it from this exact
source behavior; the app is a VPN/network utility with no content feed.

Questionnaire answers for `1.0.15+30`:

- Violence: none of the violence categories (cartoon, fantasy, realistic,
  bloodshed, sexual violence).
- Sexual content and nudity: none.
- Profanity or crude humor: none.
- Drugs, alcohol, or tobacco: none.
- Gambling or simulated gambling: none. The app has no loot boxes, contests,
  wagering, or chance-based mechanics.
- User-generated content: no. The app has no content sharing, chat, or
  social features.
- Interacting with other users: no. The Wear companion talks only to the
  paired phone over the Wearable Data Layer.
- Sharing user location: no. The app does not use device GPS and does not
  share user location with other users or third parties.
- Digital purchases: the app itself does not sell digital goods through
  Google Play Billing in this release. Premium access is purchased through
  the public website checkout outside the app; the app does not collect card
  data.
- Mature themes, horror, or fear: none.
- Personal data collection from children: not applicable; the app is not
  directed at children.
- Ads: the app contains no ads and no advertising SDKs.

Expected result: everyone / low maturity for all three form factors. Do not
claim a rating value until Play Console shows the completed IARC certificate.
Content-rating completion is an owner publication gate, like the
`QUERY_ALL_PACKAGES` declaration, not something a local build or test can
verify.

Do not add a content-rating claim to `app_store/android/` folders until the
IARC questionnaire is actually completed in Play Console and the resulting
rating certificate is visible.

## Official Policy References

- Google Play Payments policy: https://support.google.com/googleplay/android-developer/answer/10281818
- Google Play Developer Program Policy / User Data policy: https://support.google.com/googleplay/android-developer/answer/17105854
- Google Play User Data privacy-policy requirements: https://support.google.com/googleplay/android-developer/answer/10144311
- Google Play `QUERY_ALL_PACKAGES` policy: https://support.google.com/googleplay/android-developer/answer/10158779
- Google Play `VpnService` policy: https://support.google.com/googleplay/android-developer/answer/12564964
- Google Play foreground service requirements: https://support.google.com/googleplay/android-developer/answer/13392821

## Android TV

Phone and TV share the `android/` freeze root and the same application ID. TV is a product flavor of that tree (`LEANBACK_LAUNCHER`), not a separate freeze platform. Formal Android receipts already distinguish `android-release-apk`, `android-release-aab`, `android-tv-release-apk`, and `android-tv-release-aab`. The required Google Play TV upload target is `android-tv-aab`. It is one of the 16 required upload targets. The phone/tablet AAB (`android-phone-tablet-aab` / `android-release-aab`) and the TV APK (`android-tv-release-apk`) are not TV AAB evidence and do not replace `android-tv-aab`.

Play Console TV form-factor notes:

- Declare Android TV as a form factor of `org.winsvpn.app`, not a second package.
- TV uses D-pad / Leanback navigation. Do not claim touch-only screenshots for the TV track.
- The TV flavor inherits `QUERY_ALL_PACKAGES` from `android/app/src/main/AndroidManifest.xml`. The TV overlay in `android/app/src/tv/AndroidManifest.xml` does not remove that permission.
- The TV UI exposes the same per-app picker named `Exclude Apps From VPN (Split Tunneling)`. Per-app split tunneling is enabled for Android, including TV. Do not claim phone-only `QUERY_ALL_PACKAGES` or picker behavior.
- The Play Console `QUERY_ALL_PACKAGES` declaration remains `PENDING` for this shared application ID, including TV.
- VPN, foreground-service, and battery-exemption declarations apply only where those APIs exist on the TV device.
- Calculator camouflage is disabled on TV.
- TV listing/screenshot inventory is owner-blocked. See the inventory fields below.

## Wear OS

Wear OS ships from `wear_os/`, a separate Gradle project and freeze platform. It is a non-standalone companion: no `INTERNET` permission, no VPN tunnel, no account number or keys on the watch. Pairing uses the Wearable Data Layer only. Wear OS does not request `QUERY_ALL_PACKAGES` and does not expose the per-app picker.

Play Console Wear notes:

- Same application ID as the phone companion; Play must not offer the watch app to unpaired watches (`com.google.android.wearable.standalone=false`).
- Data safety for the watch APK: no off-device collection. Do not copy the phone Data safety matrix onto the Wear listing.
- Wear freeze receipts are independent of phone/TV receipts. A phone-only native change must not be used as Wear release evidence.
- Wear release producer is `wear_os/tools/signed_aab_receipt.py`; the AAB inspector is `wear_os/tools/assert_release_aab.py`.
- Wear listing/screenshot inventory is owner-blocked. See the inventory fields below.

## Listing / Screenshot Inventory

Play Console listing graphics are owner-held. This repository does not contain
Play listing screenshots, feature graphics, promo videos, or store-portal
approvals for phone, TV, or Wear. Do not invent those assets or treat this
document as Play Console graphics approval.

English listing copy, including what's-new drafts, lives in
`app_store/android/{phone,tv,wear}/`. Those files are not Play Console
graphics approval.

Explicit inventory fields:

- phone listing/screenshot inventory: owner-blocked
- TV listing/screenshot inventory: owner-blocked
- Wear listing/screenshot inventory: owner-blocked
