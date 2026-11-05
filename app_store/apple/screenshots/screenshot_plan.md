# Apple Screenshot Plan

Last reviewed: 2026-07-11

Use screenshots from the final submitted build. Do not upload screenshots that
show private account numbers, server credentials, private keys, raw endpoint
IPs, support-only diagnostics, or local machine paths.

Apple reference:

- https://developer.apple.com/help/app-store-connect/reference/app-information/screenshot-specifications/

## Required Sets

### iPhone

The app runs on iPhone. Provide 6.9-inch screenshots first. Apple currently
lists these accepted 6.9-inch sizes:

- 1260 x 2736 pixels portrait, or 2736 x 1260 pixels landscape.
- 1290 x 2796 pixels portrait, or 2796 x 1290 pixels landscape.
- 1320 x 2868 pixels portrait, or 2868 x 1320 pixels landscape.

Recommended capture device:

- Physical iPhone 16 Pro Max or an iPhone Pro Max simulator that produces an
  accepted 6.9-inch screenshot size.
- Apple's App Store Connect API 4.4 still names the newest large-iPhone upload
  set `APP_IPHONE_67`; the signed-in Media Manager accepts the current
  `1320 x 2868` candidate for the 6.9-inch product-page slot.

Suggested screenshot story:

1. Welcome/main state with Win's VPN branding visible.
2. Free server or account activation state, with no private account number.
3. Server/protocol selection or Smart Protocol state.
4. Connected VPN state.
5. Privacy/no-log/support state.

### Mac

The app runs on macOS. Apple currently requires Mac screenshots with a 16:10
aspect ratio. Accepted sizes include:

- 1280 x 800 pixels.
- 1440 x 900 pixels.
- 2560 x 1600 pixels.
- 2880 x 1800 pixels.

Suggested screenshot story:

1. Main Win's VPN window.
2. Free server or account activation state.
3. Smart Protocol/server state.
4. Connected VPN state.
5. Privacy/support state.

## Local Capture Notes

- iOS simulator UI smoke currently launches and captures app-visible evidence,
  but final store screenshots still need to be curated from the submitted build.
- Current candidate iPhone 6.9-inch screenshot:
  `app_store/apple/screenshots/candidates/ios-6_9/01-main.png`.
  - Re-captured on 2026-07-11 from a clean installation of the final
    current-source iPhone 16 Pro Max-size simulator build. It shows the
    native Apple MapKit Tampa Bay user-location backdrop, accessibility-safe
    activation controls, and Apple-safe purchase flow without private data.
  - Size: 1320 x 2868 pixels.
  - SHA-256:
    `b3c5150e0baccb681a3b54d63a7f0a580fcc9881637ac55d174a7cf166d05db1`.
- Current candidate Mac 16:10 screenshot:
  `app_store/apple/screenshots/candidates/macos-16_10/01-main.png`.
  - Re-captured on 2026-07-11 directly from the final current-source macOS app
    window after the exact-candidate live-tunnel gate. The selected Canada
    server remains distinct from the Florida-area coarse user-location map;
    no private data is visible.
  - Size: 2560 x 1600 pixels.
  - SHA-256:
    `a9645a95e89fd0e86806bffdba391502d971d65ac932f9034b80d2747aad03e1`.
- Re-run the live tunnel smoke after screenshot capture if any UI-only capture
  flow changes app state or configuration.
