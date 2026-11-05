# Apple Export Compliance - Winn v3 (fin_store_ios, 2026-08-11)

**Prepared by lane `fin_store_ios` on 2026-08-11. PREPARE ONLY - nothing was
uploaded or submitted. Engineering fact sheet, NOT legal advice; final
questionnaire answers are the owner + counsel's to set.**

> **RECONCILED 2026-08-25 (superseded).** This 2026-08-11 draft's claim that
> "v3 replaces the AmneziaWG/Xray datapath" is false and must not be used as the
> export/import basis. The authoritative sheets are the live
> `app_store/apple/review/export_compliance_facts.txt` and the 2026-08-11 bld
> package. Winn v3 is the PRIMARY tunnel protocol; the Winn v1 compatibility
> path REMAINS and is AWG (AmneziaWG) first, then Xray, so those engines do NOT
> leave the datapath and the fallback carrier is NOT an open item. Winn v3 uses
> X25519 (RFC 7748), ML-KEM-768 (FIPS 203), ChaCha20-Poly1305 (RFC 8439), and
> SHA-256; its optional Ed25519 + ML-DSA-65 dual-signature attestation leg is
> gated off and not active in the iOS or macOS builds.

**Gate:** as of 2026-08-11 there is no signed iOS App Store build carrying the
winn3 datapath (the only signed IPA is the stale `1.0.14+29`; `build/apple/exports/`
has no iOS export). The inventory below is the **source tree's** winn3 datapath;
it becomes a live export-compliance fact only for the exact submitted binary
that carries it. `ITSAppUsesNonExemptEncryption` is **absent** from the Runner
and PacketTunnel plists (measured), so Apple presents the encryption
questionnaire at upload - the intended flow.

## 1. What the v3 datapath is (the object being declared)

v3 is the app's **PRIMARY** tunnel protocol: a first-party, proprietary
protocol with its own handshake, key schedule, transport crypto and datapath.
It does NOT replace the AmneziaWG/Xray engines; they remain the Winn v1
compatibility path (AWG first, then Xray) used when Winn v3 cannot connect.
`WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md` Section 2 (re-verified this run):

| Role | Primitive | Design Section 2 |
|---|---|---|
| Transcript hash | SHA-256 | `crypto/sha256` |
| Chain KDF | HKDF-SHA-256 (Extract + Expand) | `crypto/hkdf` |
| Admission MAC | HMAC-SHA-256, truncated | `crypto/hmac` |
| DH | X25519 | `crypto/ecdh` |
| KEM | ML-KEM-768 (FIPS 203) | `crypto/mlkem` |
| AEAD | ChaCha20-Poly1305, 96-bit nonce | `golang.org/x/crypto/chacha20poly1305` |

**Suite identifier:** `winn3-x25519-mlkem768-chacha20poly1305-sha256`, wire
version label `winn/3`. The suite name never appears on the wire; it is input to
the transcript hash.

Net effect vs the old AWG/Xray sheet (`export_compliance_facts.txt`): the v3
PRIMARY path's **algorithms are easier to classify** (standard, enumerable - no
junk-packet/header-randomization prong on v3), but the **protocol being
first-party/self-shipped is a stronger reason to answer "non-standard / not
exempt"** under Apple's prongs. The Winn v1 AWG-first/Xray-second fallback keeps
its own classification in the same filing. This is a **re-classification, not a
carry-forward** of the old answer.

## 2. Recommended questionnaire stance (advisory, for owner + counsel)

| App Store Connect question | Recommeded at v3 | Reason |
|---|---|---|
| Does your app use encryption? | **Yes** | Tunnel AEAD + handshake + transport crypto (+ Keychain) |
| Standard-encryption exemption (OS/TLS-only) | **No** | Datapath is first-party, not confined to OS/TLS |
| Industry-standard algorithms (EXCP/mass-market ENC path) | **Yes for the algorithms; legal holds the overall call** | Algorithms are FIPS-203/standard; protocol is proprietary |
| U.S. CCATS / BIS | **Confirm with counsel** | Proprietary protocol + each enabled transport |
| France distribution | **Non-standard declaration filed** | Non-standard crypto in France |

- BIS treats encryption software as Category 5 Part 2; determine the applicable
  classification, reporting and destination requirements before relying on
  License Exception ENC.
- If distributing in France, Apple additionally requires a French encryption
  declaration for encryption implemented outside the operating system.
- Apple evaluates submitted encryption documentation case by case (~2 business
  days); complete the app description and manage Store availability **before**
  submitting documentation.

## 3. What does NOT change

- Standard platform security APIs (Apple Keychain) and Apple's NetworkExtension
  PacketTunnel framework.
- `ITSAppUsesNonExemptEncryption` stays absent - do NOT set it to `NO`, and do
  NOT claim an exemption until the determination is made.
- Any AWG/Xray **fallback carrier** still shipping in the v3 build keeps its own
  classification in the same filing. The v3 build **does** ship one: the Winn v1
  compatibility path is AWG first, then Xray (reconciled 2026-08-25), so that
  fallback's classification and disclosure stay in the same filing.

## 4. Open owner/legal items (for the report)

1. Final "does your app use encryption?" + exemption answer for the exact build.
2. The v3 build **does** ship the AWG/Xray fallback carrier (the Winn v1
   compatibility path, AWG first then Xray), so its own classification and
   fallback disclosure are carried in the same filing.
3. U.S. CCATS determination, French declaration, annual BIS/NSA mass-market
   self-classification if the ENC/5D992.c path is taken.

This lane made **no** upload, no submission, no re-signing, no credential
operation, processed no credential, and changed no existing compliance file.