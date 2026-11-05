# Apple Export Compliance - v3: engineering facts + recommended questionnaire answers

**Prepared by lane `bld_store_ios` on 2026-08-10. PREPARE ONLY. Engineering fact
sheet, NOT legal advice. Final answers belong to the owner + counsel.**

> **RECONCILED 2026-08-25 (superseded).** This 2026-08-10 draft's claim that
> "the v3 datapath replaces the AWG/Xray engine" is now false and must not be
> used as the export/import basis. The authoritative sheets are the live
> `app_store/apple/review/export_compliance_facts.txt` and the 2026-08-11
> packages. Winn v3 is the PRIMARY protocol; the Winn v1 compatibility path
> REMAINS and is AWG (AmneziaWG) first, then Xray. Winn v3 uses X25519
> (RFC 7748), ML-KEM-768 (FIPS 203), ChaCha20-Poly1305 (RFC 8439), and SHA-256;
> its optional Ed25519 + ML-DSA-65 dual-signature attestation leg is gated off
> and not active in the iOS or macOS builds.

Base files: `app_store/apple/review/export_compliance_facts.txt` (the live
operational sheet) and, for the v3 object being declared,
`docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md` Section 2. The v3 datapath
is the PRIMARY path; the AWG/Xray classification reasoning in the old sheet is
superseded for the primary datapath only and still applies to the AWG-first,
Xray-second Winn v1 fallback.

## The encryption object at v3 (verified against the design doc this lane)

| Component | Algorithm | Design-doc line |
|---|---|---|
| Transcript hash | SHA-256 | Section 2 (transcript hash) |
| Chain KDF | HKDF-SHA-256 (Extract + Expand) | Section 2 (chain KDF) |
| Admission MAC | HMAC-SHA-256, truncated | Section 2 (admission MAC) |
| DH | X25519 | Section 2 (DH) |
| KEM | ML-KEM-768 (FIPS 203) | Section 2 (KEM) |
| AEAD | ChaCha20-Poly1305, 96-bit nonce | Section 2 (AEAD) |
| Suite identifier | `winn3-x25519-mlkem768-chacha20poly1305-sha256` | Section 2 (suite id) |

All seven strings verified present in
`docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md` by direct grep this
lane.

## What does / does not change

- The app still uses Apple Keychain and Apple NetworkExtension
  PacketTunnel (verified: entitlement `packet-tunnel-provider` present in
  `ios/Runner/Runner.entitlements` and `ios/PacketTunnel/PacketTunnel.entitlements`).
- `ITSAppUsesNonExemptEncryption` remains **absent** from the iOS `Info.plist`
  (verified this lane by PlistBuddy - no ITS/export key present), so Apple will
  present its encryption questionnaire at upload. Do NOT set it to `NO` or claim
  an exemption before the determination is made.
- France: a French non-standard-crypto declaration is still indicated on the
  same reading; v3 does not relax it (proprietary protocol, non-OS crypto).

## Recommended App Store Connect questionnaire answers (label: legal-review-required)

| Question | Recommended answer | Reason |
|---|---|---|
| Does your app use encryption? | **Yes** | Tunnel AEAD + handshake + transport crypto |
| Exempt under standard-encryption exception? | **No** | First-party datapath, not confined to OS/TLS |
| Algorithms standard (mass-market ENC path)? | **Yes for the algorithms; overall call held by legal** | FIPS-203/standard and enumerable; protocol is proprietary |
| U.S. CCATS needed? | **Confirm with counsel** | Proprietary protocol is the classic CCATS trigger |
| France | **Non-standard declaration filed** | Non-standard crypto in France |

## Two v3-specific open items (owner/legal)

1. The submitted v3 build **does** ship the **AWG/Xray fallback carrier** (the
   Winn v1 compatibility path, AWG first then Xray), so its own classification
   must be carried in the same filing, and the fallback disclosure stays in
   data-safety + review notes.
2. Annual BIS/mass-market self-classification if the ENC/5D992.c path is taken.

## Operational stance (unchanged)

- Answer conservatively; complete the questionnaire and any document review
  **before** App Review submission; add Apple's compliance code only after Apple
  issues one via its process.
- Keep `ITSAppUsesNonExemptEncryption` absent.
- Keep export documents with account/legal filing detail outside source control.

Base `export_compliance_facts.txt` remains the live sheet for the current
(non-v3) build until a v3 artifact is frozen; this file is the v3-specific
delta standing on top of it.