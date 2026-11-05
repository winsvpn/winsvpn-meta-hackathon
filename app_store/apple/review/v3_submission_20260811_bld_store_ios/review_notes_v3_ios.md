# Win's VPN iOS App Review Notes - Winn v3 submission

**Prepared by lane `bld_store_ios` on 2026-08-11.** Reviewer-facing copy
explaining the VPN function and how to test it. Adapted from
`app_store/apple/review/ios_review_notes.txt` and corrected on three points this
run: the camouflage PIN is **six digits** (legacy four-digit still accepted),
**Purchase History is not collected** and must not be listed as disclosed, and
**Product Interaction is disclosed** (reconciled 2026-08-25 to the four-type
source position).

**Gate carried through everything:** no signed Apple release build carries the
winn3 datapath today; the v3 paragraph in Section 6 is a ready-to-enable block, not a
live claim.

---

## Purpose

Win's VPN is a VPN client that uses Apple's **Network Extension Packet Tunnel**
framework to provide secure connectivity. The PacketTunnel extension bundle ID
is `org.winsvpn.app.PacketTunnel`. Winn v3 is the primary tunnel protocol; if
Winn v3 cannot connect, the app uses the Winn v1 compatibility path with AWG
(AmneziaWG) first, then Xray. When connected, the app installs a full-tunnel
route and DNS posture and exposes connect/probe/disconnect states.

## How to test

1. Install and launch the iOS build (`org.winsvpn.app`).
2. Accept the app's legal/privacy prompts if they appear.
3. Set a **six-digit PIN** and use **Try Free Server** when no paid account
   number is available.
4. If the calculator safety screen is visible, enter that six-digit PIN using
   the calculator number buttons (leading-zero PINs supported, e.g. `028371`;
   a trivial all-zero or counting PIN is refused) to reveal the VPN interface.
5. Tap the normal connect action. The session line renders the negotiated
   protocol version - **Version 3** when the binary carries winn3, **Version 1**
   on the legacy datapath, or an explicit "not recognised" state otherwise.
6. Approve the iOS VPN configuration prompt if it appears.
7. Wait for the app to show connected/readiness status.
8. Use the disconnect action and confirm the status returns to disconnected.

## Calculator camouflage disclosure

For users in high-censorship environments where a visible VPN interface can
create personal risk, the app includes a functional calculator safety screen.
Entering the configured **six-digit PIN** (legacy four-digit PINs from older
installs still work at the decoy keypad) reveals the VPN interface. While that
screen is active the app uses the disclosed CalculatorIcon alternate home-screen
icon via `UIApplication.setAlternateIconName`; iOS may show its standard
icon-change confirmation. Entering the PIN restores the primary red panda
Guardian icon. The App Store product icon uses the red panda Guardian artwork,
and iOS continues to display its normal VPN status indicator while a tunnel is
active. The PIN is
verified against a salted PBKDF2 hash stored only in local app storage; the PIN
and entered digits are never transmitted.

## Payment / purchase note

The default Apple build does **not** open an external purchase website for
premium access. The premium-access flow tells users to use an existing account
number or **Try Free Server** until Apple subscription options are added through
App Store billing or another Apple-reviewed path.

## Privacy note (corrected)

The app is designed **not** to collect browsing history, DNS query contents,
traffic contents, destination activity logs, contacts, photos, health data, or
precise location. Disclosed, linked App Functionality data is limited to
**Coarse Location** (IP-derived country/region/center used only to centre the
disconnected map via MapKit; the app never requests Location Services and does
not retain the returned IP, city or postal-code fields), **Device ID** (install
ID, app info, device public key), **User ID** (account state), and **Product
Interaction** (selected VPN location, stealth mode, and Double VPN choices sent
with persistent account and device identifiers). **Purchase History is NOT
collected** - the app embeds no payment SDK and, by default, opens no external
purchase page; paid-entitlement state is reflected by the service, not collected
by the app. None of the disclosed data is used for tracking. (Note: the source
privacy manifests are already reconciled to these four types, but the live App
Store Connect answers still carry Purchase History and omit Product Interaction
and must be reconciled before submission.)

## VPN function for the reviewer

- Full tunnel: the PacketTunnel installs a default-route/utun posture with
  full-tunnel DNS; a kill-switch closes the route and requests an immediate
  platform disconnect if the tunnel drops.
- Protocol version is negotiated at session setup and surfaced in the UI
  (Version 1 / Version 3 / not recognised), so a reviewer can see which datapath
  the submitted binary runs.

## Section 6. Gated v3 paragraph (enable only against the submitted binary)

> Win's VPN connects through its own first-party VPN protocol. Connection keys
> use X25519 ECDH combined with the NIST post-quantum key-exchange standard
> ML-KEM-768 (FIPS 203), and traffic is encrypted with ChaCha20-Poly1305 with a
> SHA-256 transcript hash. No third-party VPN engine processes user traffic on
> that path.

**Ready-to-enable ONLY IF** the submitted binary actually carries the winn3
datapath (`-Wl,-u,_WinnTunnelCreateWinn3` pull in the appex,
`project.pbxproj`); otherwise it stays out of the review answers.

## Support

- https://www.winsvpn.org/support/
- support@winsvpn.org