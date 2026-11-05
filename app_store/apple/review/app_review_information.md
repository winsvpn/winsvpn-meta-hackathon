# Apple App Review Information Draft

Owner approved: 2026-08-31
Counsel review: pending
Last reviewed: 2026-08-31

Use this as the copy source for App Review Information. Do not commit private
review-only account passwords or Apple account contact details here.

There is no current 1.0.17+34 Apple candidate or runtime receipt. This draft
does not authorize upload.

## Contact

- Contact name: Enter the Apple Developer account owner's App Review contact in
  App Store Connect.
- Contact phone: (424) 946-7876
- Contact email: support@winsvpn.org

## Demo Access

- Demo account required: No.
- Reviewers can use Try Free Server when no paid account number is available.
- No paid account number, password, private key, or server credential is needed
  for the normal review path.

## Review Notes Summary

Win's VPN is a universal-purchase iOS and macOS VPN client using Apple's Network
Extension Packet Tunnel framework. Both platform apps use bundle ID
`org.winsvpn.app`, and both PacketTunnel extensions use
`org.winsvpn.app.PacketTunnel`.

The iOS app and the embedded watchOS companion use the device-visible name
Win's VPN. The iOS IPA embeds that watchOS companion
(`org.winsvpn.app.watchkitapp`). It is a non-VPN remote for the iPhone: it does
not run Network Extension, does not start a tunnel, and cannot approve the iOS
VPN permission prompt. The macOS app uses the Win's VPN device name and does
not embed watchOS. This 1.0.17+34 Apple submission is not an Apple TV app.

To test:

1. Install and launch the build.
2. Accept the app's legal/privacy prompts if shown.
3. On iOS, set a six-digit PIN. Fresh enrollment refuses repeated digits,
   counting sequences, and repeating patterns. Use the six-digit PIN the
   reviewer set. Do not use a trivial all-zero or counting PIN. If the iOS
   calculator safety screen is visible, enter that six-digit PIN. Leading-zero
   PINs that are not trivially guessable are accepted.
4. Use Try Free Server.
5. Start the VPN connection.
6. Approve the OS VPN/network permission prompt if shown. The watch companion
   cannot complete this step.
7. Wait for the app to show connected/readiness status.
8. Disconnect and confirm the app returns to disconnected state.

The calculator is a disclosed safety screen for users in high-censorship
environments. While it is active, the iOS/iPadOS home-screen icon changes to the
bundled `CalculatorIcon` using Apple's alternate-icon API and may show Apple's
standard confirmation. Entering the configured PIN restores the primary red
panda Guardian icon. The App Store product icon uses the red panda Guardian
artwork. Its PIN verifier is stored locally as a salted PBKDF2 hash and is not
transmitted.

The four linked App Functionality privacy types are Coarse Location, User ID,
Device ID, and Product Interaction. They are not used for tracking. Product
Interaction covers selected VPN location, stealth mode, and Double VPN choices
sent with persistent account and device identifiers. Purchase History is not
collected.

The Apple build's Premium Access Info button opens the developer's home page,
https://www.winsvpn.org, in the user's browser. The app embeds no payment SDK,
offers no in-app purchase, and does not open a checkout or payment page. Users
can use an existing Win's VPN account number or Try Free Server.

The owner approved the conservative App Store Connect export answers on
2026-08-31. Counsel review, export classification, filings, supporting
documentation, exact-artifact verification, and every live App Store Connect
action remain pending.

Support URL: https://www.winsvpn.org/support/
