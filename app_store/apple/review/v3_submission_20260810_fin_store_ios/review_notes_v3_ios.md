# App Review notes - v3 release: VPN function explained (iOS)

**Prepared by lane `fin_store_ios` on 2026-08-10. PREPARE ONLY.**

> **RECONCILED 2026-08-25 (superseded).** This 2026-08-10 draft is superseded
> by `app_store/apple/review/ios_review_notes.txt` and the 2026-08-11 packages.
> The privacy note below is stale: the disclosed linked App Functionality types
> are **Coarse Location, Device ID, User ID, and Product Interaction** (selected
> VPN location, stealth mode, Double VPN); **Purchase History is NOT collected**.
> Winn v3 is the primary protocol; the Winn v1 fallback is AWG first, then Xray.

Replacement body for `app_store/apple/review/ios_review_notes.txt` /
`app_store/apple/review/app_review_information.md` review-notes text when the
submitted iOS binary is the v3 build. The current notes are functionally fine;
the delta is (a) a first-party-engine paragraph (GATED on the binary actually
running winn3), and (b) a version/session-line reconciliation requirement so the
store does not claim what the in-app session line does not show.

## Purpose line (unchanged, both builds)

Win's VPN is a **VPN client** that uses Apple's **Network Extension Packet
Tunnel framework** to provide secure VPN connectivity. The PacketTunnel
extension bundle ID is `org.winsvpn.app.PacketTunnel`. The bundle ID of the
app itself is `org.winsvpn.app`.

## How the VPN function works (WHAT TO EXPLAIN - reviewer-facing)

1. The user launches the app and accepts the legal/privacy prompts.
2. The user enters a four-digit PIN or uses the free server path
   ("Try Free Server") - no paid account, password, private key or server
   credential is required for review.
3. If the **calculator safety screen** is visible, enter the configured PIN with
   the calculator number buttons to reveal the VPN interface (leading-zero PINs
   supported, e.g. `0000`). The calculator is a disclosed safety screen for
   users in high-censorship environments; while active, the home-screen icon
   changes to the bundled CalculatorIcon via the alternate-icon API (iOS may show
   its standard confirmation). The PIN verifier is a salted PBKDF2 hash stored
   only locally and never transmitted.
4. The user taps the connect action and approves the **iOS VPN permission
   prompt**.
5. The app establishes the encrypted tunnel through the PacketTunnel extension,
   which receives configuration and status via the App Group and shared Keychain.
6. The app shows connected/readiness status; the user browses, then disconnects
   and the app returns to disconnected state.

## First-party protocol paragraph - ADD ONLY WHEN THE SUBMITTED BINARY RUNS V3

Gate: `E2E_MATRIX_MEASURED_20260810.md` - zero of five platforms carry v3 on a
signed release build as of 2026-08-10. Use this paragraph only after the exact
iOS binary is verified (from its symbols) to run the winn3 datapath:

```text
Tunnel encryption on this build is provided by Win's VPN's own first-party
protocol (Winn Protocol v3), which performs its handshake, key exchange
(X25519 + NIST ML-KEM-768) and encryption (ChaCha20-Poly1305) inside the app's
own PacketTunnel extension. No third-party VPN engine carries user traffic on
this path. Per-session protocol keys are ephemeral and cleared at disconnect.
```

Until the gate is clean, keep the engine-neutral phrasing already in the notes:
"The PacketTunnel extension receives tunnel configuration and status through the
App Group and shared Keychain, then starts or stops the tunnel."

## Version/session-line reconciliation (MUST do at submission)

The in-app session-detail line renders the **negotiated** protocol version
(`lib/winn_session_descriptor.dart`): `Version 1`, `Version 3`, or "Version not
recognised by this app" - and the store "What's New" (and this note if it
mentions v3) must match the **submitted binary**. If the store says v3 but the
user's session line shows Version 1, the app's own "Verify No Log Policy" can be
read as contradicting the store - a review rejection and a trust break
(`RELEASE_COPY_WINN3_DRAFT_20260810.md` Section 2 App Store note + Section 4.2 footnotes).

## Payment / purchase note (unchanged)

The default Apple build does not open an external purchase website for premium
access; it directs users to an existing account number or Try Free Server. No
App Store In-App Purchase is configured in this binary.

## Privacy note (inertial - reconciles with the nutrition label)

Designed not to collect browsing history, DNS query contents, traffic contents,
destination activity logs, contacts, photos, health data, or precise location.
Coarse Location, User ID, Device ID, and Product Interaction (selected VPN
location, stealth mode, Double VPN choices) are disclosed as linked App
Functionality, not tracking. Purchase History is NOT collected - the app embeds
no payment SDK and opens no external purchase page by default. The app does not
request Apple's Location Services permission.

## Demo account

**Demo account required: No.** Reviewers use "Try Free Server" - seeded free
access with no credentials. This matches the live ASC setting
(`app_review_information.md` -> Demo Access) and the owner packet's
no-demo-account decision. If the reviewer-specific free pool ever becomes
unavailable, provide a review-only account number via App Store Connect's
review access - but that is an owner action and is NOT required for this build.

## Support

https://www.winsvpn.org/support/ - support@winsvpn.org