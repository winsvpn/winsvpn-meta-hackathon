# App Review notes - iOS: the VPN function explained

**Prepared by lane `bld_store_ios` on 2026-08-10. PREPARE ONLY.**

> **RECONCILED 2026-08-25 (superseded).** This 2026-08-10 draft is superseded
> by `app_store/apple/review/ios_review_notes.txt` and the 2026-08-11 packages.
> The privacy note at line ~97 is stale: the disclosed linked App Functionality
> types are **Coarse Location, Device ID, User ID, and Product Interaction**
> (selected VPN location, stealth mode, Double VPN); **Purchase History is NOT
> collected**. Winn v3 is the primary protocol; the Winn v1 fallback is AWG
> first, then Xray.

Purpose line, bundle IDs, contractor names, and contact verified this lane:
- Host bundle ID `org.winsvpn.app`; PacketTunnel extension
  `org.winsvpn.app.PacketTunnel` (`ios/Runner.xcodeproj/project.pbxproj`).
- NetworkExtension entitlement `packet-tunnel-provider` present in both
  `Runner.entitlements` and `PacketTunnel.entitlements`.
- Display name `Win's VPN` (iOS `Info.plist` `CFBundleDisplayName`).

## Purpose line (both builds)

Win's VPN is a **VPN client** that uses Apple's **Network Extension Packet
Tunnel framework** to provide secure VPN connectivity. The PacketTunnel
extension bundle ID is `org.winsvpn.app.PacketTunnel`; the app bundle ID is
`org.winsvpn.app`.

## How the VPN function works (reviewer steps)

1. Install and launch the app.
2. Accept the legal/privacy prompts if shown.
3. Use the **Try Free Server** path (verified: `Try Free Server (Limited
   Speed)` button in `lib/main.dart`) - no paid account, password, private key
   or server credential is required for review.
4. **PIN length (current build): 6 digits.** Set the 6-digit PIN when prompted.
   A legacy 4-digit PIN from a pre-existing older install is still accepted at
   the decoy keypad, but a fresh install enrolls a **6-digit** PIN - enter all
   six digits. (Verified: `kCamouflagePinLength = 6`,
   `kLegacyCamouflagePinLength = 4`, `lib/camouflage_policy.dart:379,385`.)
   Leading-zero PINs are supported.
5. If the **calculator safety screen** is visible, enter that PIN using the
   calculator number buttons to reveal the VPN interface. The calculator is a
   disclosed safety screen for users in high-censorship environments; while
   active, the iOS home-screen icon changes to the bundled `CalculatorIcon` via
   the alternate-icon API (`UIApplication.setAlternateIconName`, verified in
   `ios/Runner/AppDelegate.swift`). iOS may show its standard icon-change
   confirmation. Entering the correct PIN restores the primary Win's VPN icon.
6. Tap connect; approve the iOS **VPN configuration permission prompt**.
7. The PacketTunnel extension starts the tunnel, receives configuration and
   status via the App Group and shared Keychain.
8. Wait for connected/readiness status; browse; then disconnect and confirm the
   app returns to disconnected state.

## PIN-credential privacy fact

The PIN verifier is a **salted PBKDF2 hash** stored only locally
(`format = 'pbkdf2-sha256-v1'`, readline in `lib/local_security.dart`); the PIN
and its digit-entry buffer are never transmitted to Win's VPN or any third
party. There is also a separate 6-digit duress code kept as a PBKDF2 envelope.

## First-party protocol paragraph - GATED (use only when the submitted binary runs v3)

Gate source: the continuity brief and E2E matrix state **no signed release
build carries v3 on any platform as of 2026-08-10**; this lane independently
confirmed the only signed iOS IPA under the repo is the stale `1.0.14+29`
candidate. After the exact iOS binary is symbol-verified to run the winn3
datapath, add:

```text
Tunnel encryption on this build is provided by Win's VPN's own first-party
protocol (Winn Protocol v3), which performs its handshake, key exchange
(X25519 + NIST ML-KEM-768) and encryption (ChaCha20-Poly1305) inside the app's
own PacketTunnel extension. No third-party VPN engine carries user traffic on
this path. Per-session protocol keys are ephemeral and cleared at disconnect.
```

Until the gate is clean, keep the engine-neutral phrasing already in the notes.

## Version/session-line reconciliation (MUST do at submission)

The in-app session-detail line renders the **negotiated** protocol version  -
`Version 1`, `Version 3`, or "Version not recognised by this app"
(`lib/winn_session_descriptor.dart`). The store "What's New" and these notes
must match the **submitted binary**. If the store claims v3 but the user's
session line shows Version 1, the app's "Verify No Log Policy" can read as
contradicting the store - a review rejection and a trust break.

## Camouflage disclosure (required, both builds)

The calculator safety screen and the alternate launcher icon are **disclosed
here for App Review**. They are not hidden functionality: they are a
threat-model feature for users in high-censorship environments. The App Store
product icon uses the Win's VPN artwork; iOS continues to display its normal
VPN status while a tunnel is active.

## Payment / purchase note

The default Apple build does not open an external purchase website for premium
access; it directs users to an existing account number or Try Free Server. No
App Store In-App Purchase is configured in this binary.

## Privacy note

Designed not to collect browsing history, DNS query contents, traffic contents,
destination activity logs, contacts, photos, health data, or precise location.
Coarse Location, User ID, Device ID, and Product Interaction (selected VPN
location, stealth mode, Double VPN choices) are disclosed as linked App
Functionality, not tracking. Purchase History is NOT collected - the app embeds
no payment SDK and opens no external purchase page by default. The app does not
request Apple's Location Services permission.

## Demo account

**Demo account required: No.** Reviewers use Try Free Server - seeded free
access with no credentials. If the free pool ever becomes unavailable, the
owner may add a review-only account number via Asc review access (owner
action, not required for this build).

## Support

https://www.winsvpn.org/support/ - support@winsvpn.org

## Internal QA status (current build, per in-tree review notes)

The current signed iOS candidate passed signed installation and launch on a
physical iPhone 16 Pro Max, live VPN connect/probe/disconnect, full-tunnel DNS
and IPv6 leak-protection checks, and clean disconnect. The signed QA lane
preserves and restores the user's existing PIN, settings, cached node data,
client keypair, and VPN configuration after its tunnel test.