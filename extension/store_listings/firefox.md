# Firefox listing text

Status: LOCAL LISTING TEXT ONLY. No Firefox Add-ons draft or AMO item exists. Store work stays BLOCKED until a real Firefox Add-ons upload receipt binds the exact unsigned `firefox-extension-package` bytes. Missing owner or store evidence stays BLOCKED. No Firefox Add-ons item, AMO listing URL, upload receipt, approval, public URL, or screenshots are recorded here. A Chrome Web Store or Microsoft Edge Add-ons identity, ZIP, or receipt is not Firefox evidence. Listing evidence: BLOCKED. Store evidence: BLOCKED. Upload authorized: no. Publication authorized: no.

## Listing fields

- Store: `Firefox Add-ons`
- Upload target: `firefox-extension-package`
- Application companion release: `1.0.17+34`
- Name: `Win's VPN Proxy`
- Package version: `1.0.17`
- Gecko ID: `companion@winsvpn.org`
- Short description: `Routes chosen sites through Win's VPN. Requires its desktop app to be installed, running, and connected. Not a VPN on its own.`
- Detailed description: Win's VPN Proxy routes Firefox website traffic to an
  authenticated local proxy provided by the Win's VPN desktop app. The desktop
  app and browser bridge must be installed, the app must be running, and its
  tunnel must be connected before the extension routes anything. You can route
  all Firefox sites or only the sites you list, with explicit per-site bypasses
  for traffic you choose to send normally. A routed site opened over plain HTTP
  is refused on this computer and will not load. This extension affects Firefox only.
  It is not a standalone VPN, cannot open or verify the tunnel, and does not
  encrypt traffic itself. When routing is armed but the local proxy is not
  available, in-scope sites are blocked instead of being sent normally.
- Privacy statement: The extension does not make remote network requests of its
  own. It exchanges tunnel state and a short-lived proxy credential with the
  Win's VPN desktop app through local native messaging. Routed Firefox traffic
  is sent to the app's authenticated loopback proxy. The package declares
  Firefox `data_collection_permissions` as `none`; optional site access is
  requested only after a user action in the options page.
- Support URL: `https://www.winsvpn.org/support/`
- Privacy policy URL: `https://www.winsvpn.org/browser-extension-privacy/`
- Privacy policy status: owner approved August 31, 2026; counsel review pending. This does not state or imply counsel review.
- Category: owner-blocked.
- License: owner-blocked.
- Privacy practices: BLOCKED.
- JavaScript transform: whitespace-only minification of authored `extension/src`. Identifier mangling is forbidden.
- Reviewer source: authored `extension/src`.
- Store ID status: declared Gecko ID. This is the Firefox listing identity, not Mozilla review, not an AMO listing ID, and not a Chromium placeholder.
- Mozilla store review: none.
- Native-host name: `org.winsvpn.bridge`
- Native-host template: `tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json`
- Native-host allowed_extensions: `companion@winsvpn.org`
- Unsigned upload archive: `extension/dist/wins-vpn-companion-firefox.xpi`
- Unsigned upload archive alias: `extension/dist/wins-vpn-companion-firefox.zip`
- Archive signed: no. The upload archive must stay unsigned: no Mozilla `META-INF` signer, no packed `key`, and no `_metadata`. Firefox Add-ons signing is not present without Mozilla evidence.
- Upload authorized: no.
- Publication authorized: no.
- Credentials authorized: no.
- AMO listing URL: none.
- Upload receipt: none.
- Screenshots: none captured. Required before upload: at least one 1280x800 PNG
  or JPEG from the exact Firefox package.

## Permission explanation

- `proxy`: applies the local routing configuration selected by the user.
- `nativeMessaging`: obtains local tunnel state from the Win's VPN desktop app through `org.winsvpn.bridge`.
- `storage`: stores the user's routing choices and local proxy-extension state.
- `privacy`: applies browser leak-protection settings while routing is armed.
- `declarativeNetRequest`: blocks selected traffic when protected routing is not available.
- `alarms`: refreshes local tunnel-state checks after background suspension.
- `activeTab`: reads only the active tab when the user chooses to add that site.
- `webRequest` and `webRequestAuthProvider`: answer the authenticated local proxy's
  connection challenge. `webRequest.onAuthRequired` is the only registered
  `webRequest` event.
- `optional_host_permissions` (`<all_urls>`): requested only after a user action
  in the options page so `proxy.onRequest` can select per-site routes and
  `webRequest.onAuthRequired` can answer the local proxy. Not granted at
  installation. While routing is on, `proxy.onRequest` evaluates each request
  address in memory to choose route or direct; it does not store, log, or send
  that address off the computer. If access is declined, the extension fails
  closed and does not route.

## Native-host and desktop-app linkage

The Firefox ZIP or XPI does not contain the native host. Routing stays
fail-closed until the Win's VPN desktop app for 1.0.17+34 and
`org.winsvpn.bridge` are present and the tunnel is active. The live Firefox host
template already names `companion@winsvpn.org` in `allowed_extensions`, matching
the declared Gecko ID. Chrome and Edge placeholders are not Firefox evidence.

## Pre-submission checklist

- [ ] Exact unsigned Firefox ZIP or XPI passed local package and privacy verification.
- [ ] Final listing copy was checked against the exact package manifest.
- [ ] Store-required screenshots and promotional artwork were captured from the exact Firefox build.
- [ ] Firefox Add-ons developer account and listing identity were verified by the owner.
- [ ] Native-host Firefox origin was checked against the declared Gecko ID.
- [ ] `https://www.winsvpn.org/browser-extension-privacy/` resolves over public HTTPS before the listing cites it.
- [ ] Firefox Add-ons license, privacy-practices answers, and reviewer-source disclosure for whitespace-only minified JavaScript remain owner-blocked.
- [ ] Portal upload, review, approval, and public URL each have separately recorded evidence.
