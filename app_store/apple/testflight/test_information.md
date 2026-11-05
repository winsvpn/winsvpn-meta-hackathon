# Apple TestFlight Information Draft

Last reviewed: 2026-07-09

## Beta App Description

Win's VPN is a VPN client for iPhone and Mac. This TestFlight build validates
account activation, Try Free Server, the Winn v3 primary connection flow with
the Winn v1 AWG then Xray ordered compatibility path, Apple
Packet Tunnel integration, disconnect behavior, and support/privacy links.

## What To Test

1. Launch the app and review the first-run legal/privacy flow.
2. Use Try Free Server without entering payment information.
3. Approve the OS VPN/network permission prompt if shown.
4. Connect, wait for the app to report ready/connected state, then browse a
   public HTTPS page.
5. Disconnect and confirm the app returns to disconnected state.
6. Confirm support and privacy links open to public HTTPS pages.

## Feedback Email

support@winsvpn.org

## Demo Credentials

No demo credentials are required for the first TestFlight build. Use Try Free
Server for review/testing unless the owner later provides a private review-only
account through App Store Connect.
