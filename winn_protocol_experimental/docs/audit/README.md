# Winn Protocol v3 - Audit Readiness Package

This directory is written for an external security auditor. It exists so that a
scoping call can start from measured facts instead of from a demo, and so that
billed hours are spent on the code that matters rather than on discovering the
shape of the tree.

Prepared for outreach to OTF and OSTIF.

## Documents

| # | Document | What it answers |
|---|---|---|
| 1 | [01-THREAT-MODEL.md](01-THREAT-MODEL.md) | Who the adversary is, what counts as a finding, what is explicitly out of scope |
| 2 | [02-ARCHITECTURE-AND-DATA-FLOW.md](02-ARCHITECTURE-AND-DATA-FLOW.md) | How a session is established, where keys live, how the carrier abstraction works |
| 3 | [03-SECURITY-CODE-MAP.md](03-SECURITY-CODE-MAP.md) | Which packages handle attacker-controlled input or key material, ranked by exposure |
| 4 | [04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md) | What is incomplete, what is unproven, what worries us |
| 5 | [05-BUILD-AND-REPRODUCTION.md](05-BUILD-AND-REPRODUCTION.md) | Build all targets, run tests, run fuzzers, stand up a two-endpoint session |
| 6 | [06-DEPENDENCY-INVENTORY.md](06-DEPENDENCY-INVENTORY.md) | Every dependency, its version, its licence, and why it is present |
| 7 | [07-LICENSING-AND-COPYRIGHT-FINDINGS.md](07-LICENSING-AND-COPYRIGHT-FINDINGS.md) | Third-party code in the tree and what it means for AGPL plus commercial dual licensing |

Licensing artifacts live at the repository root: `LICENSE`, `COPYRIGHT`,
`NOTICE`, `CLA.md`.

## Measurement provenance

Every number in this package was measured, not estimated. Unless a document
states otherwise, all measurements were taken at:

- **Snapshot:** 2026-08-03T15:21:33Z
- **Host:** darwin/arm64 (Darwin 25.6.0)
- **Toolchain:** `go version go1.26.5 darwin/arm64`
- **Module:** `winsvpn.local/winnprotocol`
- **Working tree:** `/Users/owner/Documents/wins/source/wins_vpn/winn_protocol_experimental/`

Where a claim could not be established from the code, it is marked
**UNVERIFIED** rather than guessed. Where a claim is a reading of an
implementation rather than a measurement, it is attributed to a file and a
symbol.

### The tree moves, and it moved a lot

Four other workstreams were editing this tree while this package was written.
This is not a caveat; it is a measurement.

Over a **25-minute window**, from 15:11Z to 15:36Z:

| Metric | 15:11Z | 15:21Z (snapshot) | 15:36Z |
|---|---|---|---|
| `internal/` packages | 39 | 40 | **42** |
| Directories with Go code | 92 | 93 | **95** |
| Non-test lines | 109,592 | 111,279 | **111,914** |
| Fuzz targets | 23 | 24 | 24 |

Five substantive changes landed inside that window:

- **Caller-supplied socket adoption** for the HTTP/3 and HTTP/2 carriers
  (10:42 to 10:54 local), which **invalidates a previously circulated statement
  that this was missing and blocking Android**.
- **`internal/revocation`** (11:15 local), a new 733-line package, plus new
  `-device-revocation-list` flags on `cmd/winn-carrier-server`.
- **`tlsconfig.ApplyCoverProfile`** (11:20 local), a new anti-active-probing
  TLS profile that deliberately permits TLS 1.2 and currently has zero callers.
- **`internal/connlimit`** and **`internal/decoy`** (after 11:30 local), which
  appeared too late to be examined at all and are **not described anywhere in
  this package**.
- A new fuzz target, `internal/carrier/framing_fuzz_test.go`.

**Consequences an auditor must know:**

1. **Line numbers in this package are snapshot-relative.** The durable anchor
   is the file path plus the symbol name. If a cited line does not contain what
   a document says, grep for the named symbol before concluding the document is
   wrong.
2. **`internal/connlimit` and `internal/decoy` are unexamined.** A package named
   `decoy` is self-evidently relevant to the top-ranked asset in the threat
   model. It arrived too late to review.
3. **This tree should be frozen before it is handed to an auditor.** Scoping a
   paid engagement against a tree that gains a package every fifteen minutes
   will produce findings against code that no longer exists.

Re-run the commands in
[05-BUILD-AND-REPRODUCTION.md, section 8](05-BUILD-AND-REPRODUCTION.md#8-re-measuring-this-packages-numbers)
against whatever commit is handed over, and treat differences as drift to be
reconciled, not as errors in this package.

## Corrections to previously circulated descriptions

Some earlier internal and external descriptions of this protocol were wrong.
They are corrected here so that the errors are not carried into an engagement.
Each correction is evidenced in the linked document.

| Previously said | Measured reality | Where |
|---|---|---|
| "Ed25519 signatures" | The session protocol signs with **ML-DSA-65 and ML-DSA-87** (FIPS 204, via `cloudflare/circl`) plus **ECDSA P-384** in X.509. Ed25519 appears only in the separate `cmd/winn-phase1-*` anchor-trust subsystem and signs nothing in the session protocol. | [02](02-ARCHITECTURE-AND-DATA-FLOW.md#3-the-hybrid-post-quantum-construction) |
| "HKDF over SHA3" | There is **no SHA-3 and no SHAKE anywhere in the tree**. There is **no HKDF in production code** (one import, in a test file). The hash used throughout is **SHA-256**. | [02](02-ARCHITECTURE-AND-DATA-FLOW.md#3-the-hybrid-post-quantum-construction) |
| "ML-KEM-768 and ML-KEM-1024 alongside X25519" as an in-repo construction | Correct as a *description of what is negotiated*, but the ML-KEM implementation, the X25519 implementation, and the hybrid combiner are **all in the Go standard library**, reached through `tls.CurveID` constants. This repository contains no KEM arithmetic and no combiner. That is a deliberate policy, and it materially narrows the crypto review surface. | [02](02-ARCHITECTURE-AND-DATA-FLOW.md#3-the-hybrid-post-quantum-construction) |
| "HTTP/2, HTTP/3 and MASQUE cannot accept a caller-supplied socket" | **No longer true as of 2026-08-03 10:54.** Both carriers now implement caller-supplied socket adoption. What remains unproven is whether an Android host can drive it end to end. | [04](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md#22-android-the-socket-seam-exists-the-end-to-end-proof-does-not) |
| "builds for 9 targets" | **5** distinct GOOS/GOARCH tuples, producing **42** release binaries. The "9" appears to have counted the same five tuples written in two notations. | [05](05-BUILD-AND-REPRODUCTION.md#2-release-build-matrix) |
| "8 existing fuzz targets" | **24** fuzz targets are defined. The release gate fuzzes **9** of them, for 80 seconds total. The other 15 run only as seed-corpus unit tests. | [05](05-BUILD-AND-REPRODUCTION.md#4-fuzzing) |
| "AmneziaWG appears in only 1 of 39 internal packages" | Correct, and worth keeping: `internal/directawg` is the only `internal/` package that references it. For completeness, the wider footprint is 14 directories once `datapath/`, `cdatapath/` and 9 `cmd/` harnesses are counted. | [03](03-SECURITY-CODE-MAP.md) |

## How to read this package

If you have one hour, read [03-SECURITY-CODE-MAP.md](03-SECURITY-CODE-MAP.md)
and section 1 of
[04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md).
Between them they tell you which of the 92 package directories are worth your
time and what we already believe is broken.
