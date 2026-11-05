# Chrome Web Store draft

Status: BLOCKED. Local draft only. BLOCKED until a real Chrome Web Store upload receipt binds the exact unsigned `chrome-extension-package` bytes. Missing owner or store evidence. An owner-authenticated draft ID is recorded. No upload receipt, approval, public URL, or screenshots are recorded here. A Microsoft Edge Add-ons identity, ZIP, or receipt is not Chrome evidence. Listing evidence: BLOCKED. Store evidence: BLOCKED. Upload authorized: no. Publication authorized: no.

## Listing fields

- Store: `Chrome Web Store`
- Upload target: `chrome-extension-package`
- Application companion release: `1.0.17+34`
- Name: `Win's VPN Proxy for Chrome`
- Package version: `1.0.17`
- Short description: `Routes chosen HTTPS sites through the Win's VPN desktop tunnel. Not a VPN on its own; requires the connected desktop app.`
- Detailed description: Win's VPN Proxy for Chrome sends HTTPS sites to an
  authenticated local proxy installed with the Win's VPN desktop app release
  1.0.17+34. Choose all HTTPS sites with optional bypasses, or only the sites
  you list. The extension routes only after the desktop app reports that its
  tunnel is connected and the local proxy is ready. A routed site opened over
  plain HTTP is refused on this computer and will not load. Sites outside the
  selected proxy scope use the browser's ordinary connection. It is not a standalone VPN
  and cannot open a tunnel without the desktop app.
- Privacy statement: The package does not make remote network requests. It
  communicates locally with the Win's VPN desktop native-messaging bridge. It
  does not request host access at installation; optional site access is
  requested only after a user action in the options page.
- Support URL: `https://www.winsvpn.org/support/`
- Privacy policy URL: `https://www.winsvpn.org/browser-extension-privacy/`
- Privacy policy status: owner approved August 31, 2026; counsel review pending. This does not state or imply counsel review.
- Category: owner-blocked.
- Privacy practices: BLOCKED.
- JavaScript transform: whitespace-only minification of authored `extension/src`. Identifier mangling is forbidden.
- Store ID: `lnehjdblendkagjbmdclepjalahdhbbn`. Owner-authenticated draft only. Not publication evidence.
- Store ID status: owner-authenticated draft. Not an approved or published Chrome Web Store listing.
- Native-host name: `org.winsvpn.bridge`
- Native-host template: `tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json`
- Native-host allowed origin: `chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/`
- Unsigned upload archive: `extension/dist/wins-vpn-companion-chrome.zip`
- Archive signed: no. The upload ZIP must stay unsigned: no CRX wrap, no packed `key`, no `META-INF`, and no `_metadata`.
- Upload authorized: no.
- Publication authorized: no.
- Credentials authorized: no.
- Upload receipt: none.
- Screenshots: none captured. Required before upload: at least one 1280x800 or
  640x400 PNG or JPEG from the exact Chrome package.
- Small promo tile 440x280: pending. Not captured.

## Permission explanation

- `proxy`: applies the local routing configuration selected by the user.
- `nativeMessaging`: obtains local tunnel state from the Win's VPN desktop app through `org.winsvpn.bridge`.
- `storage`: stores the user's routing choices and local proxy state.
- `privacy`: applies browser leak-protection settings while routing is armed.
- `declarativeNetRequest`: blocks selected traffic when protected routing is not available.
- `alarms`: refreshes local tunnel-state checks after background suspension.
- `activeTab`: reads only the active tab when the user chooses to add that site.
- `webRequest` and `webRequestAuthProvider`: answer the authenticated local proxy's
  connection challenge. The extension does not register URL-reading request listeners.
- `optional_host_permissions` (`<all_urls>`): requested only after a user action
  in the options page so `webRequest.onAuthRequired` can answer the local proxy.
  Not granted at installation. If declined, the proxy extension fails closed and does
  not route.

## Native-host app linkage

The Chrome ZIP does not contain the native host. Routing stays fail-closed until
the Win's VPN desktop app for 1.0.17+34 and `org.winsvpn.bridge` are present and
the tunnel is active. The live Chrome host template binds the owner-authenticated
draft ID `lnehjdblendkagjbmdclepjalahdhbbn`, but its host-binary path remains
`PLACEHOLDER_ABSOLUTE_PATH_TO_HOST`. The draft ID is not an upload receipt,
approval, or publication. A packaging step must render an absolute host path
before installation.

## Pre-submission checklist

- [ ] Exact unsigned Chrome ZIP passed local package and privacy verification.
- [ ] Final listing copy was checked against the exact package manifest.
- [ ] Store-required screenshots and promotional artwork were captured from the exact Chrome build.
- [ ] Chrome Web Store developer account and listing identity were verified by the owner.
- [ ] Native-host Chrome origin matches the owner-authenticated draft ID and the template host path is rendered to an absolute installed path.
- [ ] `https://www.winsvpn.org/browser-extension-privacy/` resolves over public HTTPS before the listing cites it.
- [ ] Store privacy-practices answers and reviewer-source disclosure for whitespace-only minified JavaScript remain owner-blocked.
- [ ] Portal upload, review, approval, and public URL each have separately recorded evidence.
