# Apple Export Compliance - Winn v3 (engineering fact sheet)

**Prepared by lane `bld_store_ios` on 2026-08-11.** Verification only and
**legal-review-required**. Nothing was uploaded or submitted. This fact sheet
answers the App Store Connect encryption questionnaire from the engineering
side; the owner + counsel make the legal classification.

**Gate carried through everything:** as of 2026-08-11 the only signed iOS App
Store IPA anywhere is the stale `1.0.14+29` (sha `1f92c7e2...`), and
`build/apple/exports/` has no iOS export. The v3 inventory below documents the
**source tree's** winn3 datapath; it becomes a live export-compliance fact only
for the exact submitted binary that carries it.

---

## 1. Encryption inventory - re-verified against the design doc this run

`docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md` Section 2 (spot-checked at
lines 75-92 and the suite id at lines 90, 607):

| Role | Primitive | Design Section 2 source |
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

The app is a **VPN client** and uses encryption for tunnel transport and secure
communication, so the app **does use encryption** - answer that honestly. The
primitives are industry-standard and enumerable (X25519, NIST-standard
ML-KEM-768/FIPS 203, ChaCha20-Poly1305, HKDF/HMAC/SHA-256); the **protocol
arrangement itself is first-party/proprietary**, which is the point an
export-compliance reviewer will weigh. `docs/handoff/RELEASE_COPY_WINN3_DRAFT_20260810.md`
Section 5.1 and `V3_RELEASE_NOTES_FINAL_20260810_ds_relnotesfinal.md` carry the same
inventory.

## 2. `ITSAppUsesNonExemptEncryption`

Measured this run: grep for `ITSAppUsesNonExemptEncryption` in
`ios/Runner/Info.plist` and `ios/PacketTunnel/Info.plist` returns **no hits**;
the key is deliberately absent. Consequence: Apple presents the export
questionnaire at upload, which is the intended flow. **Do not set
`ITSAppUsesNonExemptEncryption` to NO / do not claim blanket exemption** until
the exact AWG/Xray-era and v3-era payloads have a documented classification  -
the existing Apple export-compliance determination predates the standalone v3
datapath, so treat this as **re-classification, not carry-forward** of an old
answer.

## 3. Recommended questionnaire stance (advisory, for owner + counsel)

- "Does your app use encryption?" - **Yes** (VPN tunnel + key storage).
- "Does your app qualify for an exemption?" - **Answer only after counsel
  classifies the custom first-party protocol trade.** Do not pre-claim.
- BIS treats encryption software as Category 5 Part 2; determine the applicable
  classification, reporting and destination requirements before relying on
  License Exception ENC.
- If distributing in France, Apple additionally requires a French encryption
  declaration for encryption implemented outside the operating system.
- Apple evaluates submitted encryption documentation case by case (~2 business
  days); complete the app description and manage Store availability **before**
  submitting documentation, otherwise Apple cannot determine sufficiency.

Pre-existing compliance facts sheet: `review/export_compliance_facts.txt`
(authority URLs and the full owner/legal confirmation list) and the encryption
dependency list in `review/rollout_readiness.json`
(`encryption_export_documentation` blocker).

## 4. What this lane did NOT do

No upload, no submission, no re-signing, no credential operation, no change to
any existing compliance file, and no legal classification. The questionnaire
answers above are recommendations for the owner and counsel.