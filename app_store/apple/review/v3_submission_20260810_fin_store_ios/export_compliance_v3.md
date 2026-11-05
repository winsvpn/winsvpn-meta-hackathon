# Apple Export Compliance - v3 release: engineering facts + recommended answers

**Prepared by lane `fin_store_ios` on 2026-08-10. PREPARE ONLY. This is an
engineering fact sheet, NOT legal advice. Final questionnaire answers are the
owner + counsel's to set.**

> **RECONCILED 2026-08-25 (superseded).** This 2026-08-10 draft contains two
> now-false claims about the product architecture and must not be used as the
> export/import basis. The authoritative sheets are the live
> `app_store/apple/review/export_compliance_facts.txt` and the 2026-08-11
> packages. Corrections:
> 1. Winn v3 is the PRIMARY tunnel protocol, not a replacement for AWG/Xray.
>    The Winn v1 compatibility path REMAINS and is AWG (AmneziaWG) first, then
>    Xray, so those engines do NOT leave the datapath.
> 2. Winn v3 uses X25519 (RFC 7748), ML-KEM-768 (FIPS 203), ChaCha20-Poly1305
>    (RFC 8439), and SHA-256; its optional Ed25519 + ML-DSA-65 dual-signature
>    attestation leg is gated off and not active in the iOS or macOS builds.

The old sheet names AmneziaWG/Xray as the engines; the v3 primary path adds the
first-party protocol beside them rather than replacing the datapath entirely.

## What changed at v3 (the object being declared)

- The tunnel's PRIMARY path is now a **first-party, proprietary protocol**  -
  its own handshake, key schedule, transport crypto and datapath. AmneziaWG and
  Xray do NOT leave the datapath: they remain the Winn v1 compatibility path
  (AWG first, then Xray) used when Winn v3 cannot connect
  (`WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md` Section 0, reconciled 2026-08-25).
- The **algorithms inside it are standard and form a short, enumerable list**
  (design Section 2), verified in-tree this lane:

| Component | Algorithm |
|---|---|
| Transcript hash | SHA-256 |
| Chain KDF | HKDF-SHA-256 (Extract + Expand) |
| Admission MAC | HMAC-SHA-256, truncated |
| DH | X25519 |
| KEM | ML-KEM-768 (FIPS 203) |
| AEAD | ChaCha20-Poly1305, 96-bit nonce |
| Suite id | `winn3-x25519-mlkem768-chacha20poly1305-sha256` |

- Net effect on classification: the **algorithms are easier** to classify than
  the AWG obfuscation layer was (no junk-packet/header-randomization question on
  the v3 datapath), but **the protocol being proprietary/self-shipped is a
  stronger reason to answer "non-standard / not exempt"** under Apple's prongs.
  This is a re-classification, not a carry-forward.

## What does NOT change

- The app still uses standard platform security APIs (Apple Keychain) and
  Apple's NetworkExtension PacketTunnel framework.
- `ITSAppUsesNonExemptEncryption` stays **absent** from the Info.plist, so Apple
  presents its encryption questionnaire at upload. Do NOT set it to `NO`, and do
  NOT claim an exemption until the determination is made.
- France: a non-standard-crypto declaration for distribution in France remains
  required on the same reading; v3 does not relax it.

## Recommended answers to the App Store Connect questionnaire (label: legal-review-required)

| App Store Connect question | Answer at v3 release | Reason |
|---|---|---|
| Does your app use encryption? | **Yes** | Tunnel AEAD + handshake + transport crypto |
| Standard-encryption exemption (OS/TLS-only path) | **No** | Datapath is first-party, not confined to OS/TLS |
| Standard/industry-standard algorithms (EXCP / mass-market ENC path) | **Yes for the algorithms; legal holds the overall call** | Algorithms are FIPS-202/standard and enumerable; the protocol is proprietary |
| U.S. CCATS required? | **Confirm with counsel** | Proprietary protocol + each enabled transport - per the old facts sheet's own rule |
| France distribution | **Non-standard declaration filed** | Non-standard crypto in France |

## Recommended operational stance (unchanged from current facts sheet)

- Answer encryption questions conservatively.
- Keep `ITSAppUsesNonExemptEncryption` absent.
- Complete the questionnaire and any document review **before** App Review
  submission; submit Apple's compliance code only after Apple (or Apple's
  process on your classification) issues one.
- Keep export documentation outside source control if it contains
  account-specific or legal filing information.

## Open owner/legal items (for the report)

1. Final "does your app use encryption?" + exemption answer for the exact build.
2. Whether the submitted v3 build still ships any AWG/Xray **fallback carrier**  -
   **it does** (the Winn v1 compatibility path, AWG first then Xray), so its own
   classification must still be carried in the same filing, and the fallback
   disclosure stays in the Play data-safety + review notes.
3. U.S. CCATS determination, French declaration, annual BIS/NSA mass-market
   self-classification if the ENC/5D992.c path is taken.