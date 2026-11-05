# STATUS — read before repurposing this package

Two facts, both true, both easy to get wrong:

## 1. This is LIVE winn/3 code. Do NOT delete it.

`internal/masque` is the RFC 9298 CONNECT-UDP client layer of the Winn Protocol v3
**mobility / self-healing carrier** (see `../../MOBILITY_AND_CARRIER.md`). Its job is
keeping one logical VPN session alive across underlay changes (Wi-Fi ↔ mobile) and
node failover. It is a healthy, actively-maintained fork of `quic-go/masque-go v0.4.0`
with local hardening fixes (see `UPSTREAM.md`); the QUIC stack under it
(`quic-go v0.60.0`) is an unforked, CVE-clean module dependency. It has one signed
live run (`../../evidence/h3-e2e-live-prepared-20260724/`, 2026-07-24). Other lanes
own and edit this code. Deleting it, disabling it, or marking it "dead" would destroy
active winn/3 work.

## 2. It is SHELVED as a *censorship-bypass* transport (Myanmar threat model).

MASQUE was **removed from the "alternative connection initiation to bypass
censorship" lane** on 2026-08-06. It runs over QUIC/UDP-443, which — for Myanmar
specifically — is *less* likely to reach and *less* ordinary-looking than the
shipping TLS/443-behind-Cloudflare transport, and (because UDP cannot be CDN-fronted)
re-exposes the node's real IP. Its genuine value is mobility, not stealth; its own
contract disclaims the censorship claim. Do not re-propose MASQUE as a Myanmar
stealth transport without meeting the revival conditions.

**Full reasoning, verified blocker list, fork-security posture, and the four revival
conditions:** `docs/handoff/MASQUE_TRANSPORT_DECISION_20260806.md`.

Nothing in this package changed for that decision — this note is the only addition.
