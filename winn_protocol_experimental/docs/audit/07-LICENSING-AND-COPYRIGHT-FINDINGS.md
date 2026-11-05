# Winn Protocol v3 - Licensing and Copyright Findings

Measured against the tree at **2026-08-03T15:21:33Z**. See
[README.md](README.md) for measurement provenance.

**This is a code-provenance scan, not legal advice.** It exists so that
counsel and the owner can make decisions from facts rather than assumptions.
Items marked as needing counsel genuinely need counsel.

---

## The question this answers

The plan is to release under **AGPL-3.0** and to offer a **commercial licence**
alongside it. Dual-licensing requires Win's VPN Inc. to own, or to have the
right to relicense, everything it offers commercially. This document says what
in the tree complicates that.

**Bottom line: a CLA is necessary but not sufficient.** Four items sit outside
what contributor assignment can fix, and one of them is structural.

---

## 1. Current licensing state

| Artifact | Before this package | Now |
|---|---|---|
| Root `LICENSE` | **Did not exist** | AGPL-3.0 verbatim, 661 lines, fetched from `https://www.gnu.org/licenses/agpl-3.0.txt` |
| Root `COPYRIGHT` | Did not exist | Created: header convention and ownership statement |
| Root `NOTICE` | Did not exist | Created: third-party attributions |
| Root `CLA.md` | Did not exist | Created: individual and entity CLA |
| `internal/masque/LICENSE` | Existed | Unchanged. MIT, `Copyright 2024 Marten Seemann` |

**Before this work the project asserted no licence over its own code at all.**
The only licence file in the tree was a third party's.

**No source file in the tree carries a copyright header.** A tree-wide grep for
`Copyright` returns exactly one hit: `internal/masque/LICENSE`. A grep for
`SPDX-License-Identifier` returns **zero** hits.

---

## 2. Findings that complicate dual-licensing

Ordered by how hard they are to resolve.

### 2.1 AI-generated authorship - structural, and the deepest issue

**A CLA cannot fix this, because a CLA assigns rights from human contributors,
and the question here is whether copyright subsists at all.**

Artifacts throughout the tree indicate that substantial portions were produced
by AI coding agents rather than by human employees or contractors:

- `CLAUDE_TAKEOVER_BRIEF_2026-07-25.md` at the repository root
- `spikes/ios_maximum_privacy/WINN_STAGEB_TYPED_CAPTURE_GROK45_REVIEW_20260727.md`
- `spikes/ios_maximum_privacy/WINN_STAGEB_TYPED_CAPTURE_OPUS5_REVIEW_20260727.md`
- `spikes/ios_maximum_privacy/reviews/CURSOR_GROK_STAGEB_LIFECYCLE_TEST_GAPS.md`
- `spikes/ios_maximum_privacy/reviews/OPENCODE_DEEPSEEK_STAGEB_CODEC_TEST_GAPS.md`
- `cmd/winn-phase1-conservation-smoke/cli_wrapper_forwarding_opus_test.go`
- Agent-named build lanes under
  `spikes/ios_maximum_privacy/.runtime/codex-root-swift-audit/` and
  `.../cursor-grok-lifecycle-testgaps/`
- `WINN_PROTOCOL_V3_CONTINUATION_LOG.md` refers to "final Codex edits before
  pause"

**Why this matters commercially.** In the United States, works lacking
sufficient human authorship may not be copyrightable. If a meaningful share of
the tree is not copyrightable, then:

- there is less to assign, and less to license exclusively;
- a commercial licensee receives a weaker grant than they may expect;
- the AGPL's copyleft has less to bite on for those portions, which cuts both
  ways.

Other jurisdictions differ. The UK's computer-generated works provision, for
example, takes a different approach.

**UNVERIFIED and not determinable by a code scan:** what fraction of the tree is
agent-generated, and how much human direction, selection and revision was
applied to each part. That second question is the one that matters legally, and
only the owner can answer it.

**Recommendation:** raise this with counsel before offering a commercial
licence, not after. Consider keeping contemporaneous records of human
direction and review. This is the single item most likely to surprise a
commercial counterparty during diligence.

### 2.2 `internal/masque` is third-party MIT code

**Win's VPN Inc. does not and cannot own this.**

- 9 Go files in `internal/masque`, forked from `github.com/quic-go/masque-go`
  v0.4.0, source commit `03179c5407a332f0509fa8e165244e6410ac165a`.
- Licence: MIT, `Copyright 2024 Marten Seemann`, at `internal/masque/LICENSE`.
- `internal/masque/UPSTREAM.md` states that the client, request, transport and
  request-parsing files and `UPSTREAM_README.md` were **copied without changes**
  before Winn-specific repairs.
- `internal/masque/UPSTREAM_README.md` is a **verbatim copy of the upstream
  README**, itself a copyrighted work.

**Good news:** MIT to AGPL-3.0 is compatible. Relicensing the *combined work*
under AGPL-3.0 is fine, and offering the combined work commercially is fine.
Marten Seemann's MIT grant already permits sublicensing.

**The obligation that remains:** MIT requires the copyright notice and
permission notice to be included in "all copies or substantial portions of the
Software". That applies to the **commercial** distribution too, not only the
AGPL one.

**Current state of compliance:**

- Satisfied at directory level by `internal/masque/LICENSE`.
- `scripts/build_release.sh` already copies `LICENSE` and `UPSTREAM.md` into
  `third_party_licenses/` for binary releases. Good.
- `cmd/winn-sbom-augment/main.go` already emits the fork as a distinct SBOM
  component, `github.com/quic-go/masque-go` `v0.4.0-winn.1`, licence `MIT`,
  property `winsvpn:embedded-fork = true`. Good.
- **Gap:** none of the nine `.go` files carries a per-file copyright header.
  Any redistribution that separates a file from its directory breaks the notice
  condition.

**Recommendation:** add an SPDX header to the five upstream-derived Go files
(`client.go`, `conn.go`, `request.go`, `transport.go`, `proxy_request.go`)
naming Marten Seemann and MIT. The root `NOTICE` created alongside this document
covers the distribution-level obligation. Per-file headers close the rest.

**Do not** exclude `internal/masque` from the CLA scope on the theory that it
is third-party. Winn's own modifications to it, and the Winn-authored files in
the same directory (`sfv.go`, `conn_deadline_test.go`, the fuzz test), are
Winn's and must be assignable.

### 2.3 `patches/amneziawg-go-fast-handshake-v1.patch` embeds upstream source

The `patches/` directory contains exactly one patch file. It modifies
`device/constants.go` in **amneziawg-go**, changing handshake retry scheduling
only: `RekeyTimeout` 5s to 350ms, `MaxTimerHandshakes` 18 to 257,
`RekeyTimeoutJitterMaxMs` 334 to 50. The patch's own comment states that
handshake messages, keys, PSKs and authentication are unchanged.

**It contains third-party code.** A unified diff necessarily embeds upstream
text: the removed lines and roughly nine lines of surrounding context
(`RejectAfterMessages`, `RekeyAfterTime`, `RekeyAttemptTime`, `RejectAfterTime`,
`KeepaliveTimeout`, `CookieRefreshTime`, and the `const (` framing) are literal
amneziawg-go source. It is a derivative work of amneziawg-go, however small.

**Problems:**

- The patch file carries **no licence header and no copyright notice**.
- It pins **no upstream commit or release**, only abbreviated git blob hashes
  (`37a502b` to `423a2ff`), which do not identify a version.
- **No amneziawg-go LICENSE text exists anywhere in the tree.**
- **UNVERIFIED:** the licence of amneziawg-go is asserted only secondhand, in
  this repository's own prose at `OPERATIONS.md`, as permissive MIT-style. That
  assertion is not backed by an upstream licence text in the tree.

**Recommendation:** capture the upstream `LICENSE`, record the exact upstream
commit or release the patch applies to, and add a provenance header to the
patch file, mirroring what `internal/masque/UPSTREAM.md` does well.

### 2.4 GPL-2.0 runtime dependency constrains what may ship

`OPERATIONS.md` already flags this, correctly and candidly:

- pinned `amneziawg-go` carries a permissive MIT-style licence;
- pinned **`amneziawg-tools`**, which provides the `awg` command Winn executes
  to configure interfaces, carries **GPL-2.0**;
- distributing any client, appliance or server **image** containing the tools
  binary requires qualified licence review and satisfaction of
  corresponding-source and notice obligations;
- invoking the tools as a separate executable "is not a legal conclusion about
  derivative-work scope".

That last point is the right posture and should be preserved.

Also GPL-2.0 or LGPL: `ip` (iproute2), `nft` (nftables), `resolvectl`
(systemd). Winn executes all of them.

**This is a distribution and packaging exposure, not a copyright-ownership
exposure in the tree.** It does not block a CLA. It does constrain what the
commercial offering can bundle. AGPL-3.0 and GPL-2.0-only are not compatible
for combination into a single work, which is a further reason to keep the
separate-executable boundary clean and documented.

**Recommendation:** counsel should confirm the separate-executable analysis
before any image ships, and the commercial licence should be drafted so it does
not implicitly promise the right to redistribute GPL tooling.

---

## 3. Findings that do not complicate dual-licensing

Recorded so their absence is not mistaken for an unfinished scan.

| Checked | Result |
|---|---|
| `vendor/` directory | **Does not exist** |
| Copyleft dependencies | **None.** All 14 modules are BSD-3-Clause or MIT. See [06](06-DEPENDENCY-INVENTORY.md). |
| SPDX conflicts | None. Zero SPDX identifiers exist anywhere. |
| Unknown human contributors | **None found.** No `@author` tags, no `Author:` lines, no `Signed-off-by`, no `Co-authored-by`, no GitHub handles anywhere in source. |
| Email addresses in source | Four, all placeholders: `operator@winn.local`, `owner@example.invalid`, `user@db.example`, `user@gateway.example`. |
| Copied WireGuard or AmneziaWG source | **None in the tree.** `datapath/classify.go` reimplements AmneziaWG packet classification from protocol facts. The engine is executed as an external binary. |
| Copied RFC reference implementations | None found. |
| Third-party `.c`, `.h`, `.m`, `.swift`, `.java`, `.kt`, `.cpp`, `.py`, `.sh` | None. All 11 `.c`, 12 `.h` and 40 `.swift` files under `spikes/ios_maximum_privacy/` are Winn-authored. `PrivacyCore/Package.swift` declares zero external SwiftPM dependencies. |
| `schema/`, `deploy/`, `config/`, `testvectors/` | Clean, Winn-authored. |

**One build-residue note, not a tree finding:** four generated `runner.swift`
files under `spikes/ios_maximum_privacy/.build/`, `.runtime/` and
`PrivacyCore/.build/` contain SwiftPM-generated code with comments marking it as
copied from `TSCBasic` and `XCTEvents` (swift-package-manager, Apache-2.0 with
Runtime Library Exception). **These directories are gitignored**
(`spikes/ios_maximum_privacy/.gitignore`), so they are build output, not tree
content. They total roughly 1.5 GB and should not be exported.

---

## 4. Committed binaries: a notice obligation, not an ownership problem

The root `.gitignore` covers only `/bin/`, `/build/`, `/lab/`,
`/evidence/runtime/`, `*.log`, `*.test`, `coverage.out`. It does **not** cover
the following, so all would be tracked:

**Root-level executables:**

| Size | Path | Type |
|---|---|---|
| 10.1 MB | `winn-auto-e2e` | ELF x86-64, static |
| 8.6 MB | `winn-phase1-soak-controller` | Mach-O arm64 |
| 6.6 MB | `winn-datapath` | ELF x86-64, static |
| 6.0 MB | `winn-phase1-matrix-verify.exe` | PE32+ x86-64 |
| 5.6 MB | `winn-phase1-controller-close` | Mach-O arm64 |
| 5.4 MB | `winn-phase1-matrix-verify` | Mach-O arm64 |
| 4.5 MB | `winn-phase1-anchor-pin` | Mach-O arm64 |
| 4.2 MB | `matrixverify` | Mach-O arm64 |
| 3.6 MB | `evidenceverify` | Mach-O arm64 |

**`tools/winn_conformance_build_out/`:** `libwinn-datapath-darwin-arm64.a`
(11.4 MB), `libwinn-datapath-ios-arm64.a` (11.3 MB),
`winn-datapath-windows-amd64.exe` (4.6 MB), `winn-datapath-android-arm64`
(4.6 MB), `winn-datapath-darwin-arm64` (4.3 MB).

**Plus 27 `.tar.gz` evidence bundles** under `evidence/`.

These embed third-party code. `go version -m ./winn-datapath` confirms circl,
httpsfv, qpack, quic-go, uritemplate, x/crypto, x/net, x/sys, x/text, plus the
Go standard library. All are permissive, so there is **no ownership problem**,
but **binary redistribution triggers the BSD and MIT binary-form notice
obligations**, and no `NOTICE` file existed to satisfy them. The `NOTICE` file
created alongside this document closes that.

**Recommendations, in order:**

1. **Do not ship these binaries in the open-source release.** They are build
   residue with unclear provenance. `tools/winn_conformance_build_out/` in
   particular is produced by no script in the tree (see
   [05](05-BUILD-AND-REPRODUCTION.md#the-cgo-gap)) and cannot be reproduced.
2. Extend `.gitignore` to cover them before the repository is made public.
3. `winn-datapath` records `vcs.modified=true`, meaning it was built from a
   dirty tree. That alone disqualifies it from a reproducible release.

---

## 5. What the CLA must cover

Given the above, `CLA.md` at the repository root is drafted to:

- take a **copyright assignment** where permitted, with a broad exclusive
  licence as fallback in jurisdictions where assignment of future works is
  restricted;
- include an **explicit patent grant**, which AGPL-3.0 requires downstream
  anyway and which a commercial licensee will expect;
- require the contributor to **warrant originality** and to disclose
  third-party material and any employer or third-party rights;
- **explicitly cover AI-assisted contributions**, requiring the contributor to
  disclose material AI generation and to warrant they applied sufficient human
  authorship, since section 2.1 makes this the central risk;
- state plainly that Win's VPN Inc. **may relicense contributions under any
  terms, including proprietary terms**, which is the clause that makes dual
  licensing possible and which contributors must knowingly accept;
- have both an **individual** and an **entity** form.

---

## 6. Actions before going public

| # | Action | Blocking? |
|---|---|---|
| 1 | Counsel review of AI-authorship exposure (2.1) | **Yes, for the commercial licence** |
| 2 | Add SPDX headers to the five upstream-derived `internal/masque` files (2.2) | Yes |
| 3 | Capture amneziawg-go `LICENSE` and pin the upstream commit for the patch (2.3) | Yes |
| 4 | Counsel review of GPL-2.0 tooling distribution before any image ships (2.4) | Yes, for images |
| 5 | Remove committed binaries and extend `.gitignore` (section 4) | Yes |
| 6 | Confirm provenance of the three `testvectors/v2.json` PSKs and run a git-history secret scan against the real repository | Yes |
| 7 | Adopt the `COPYRIGHT` header convention across new files | No, but do it early |
| 8 | Decide whether `spikes/ios_maximum_privacy/` ships at all | No |

---

## 7. Explicit uncertainties

- **UNVERIFIED:** the fraction of the tree that is AI-generated, and the degree
  of human authorship applied. Not determinable by scanning.
- **UNVERIFIED:** the licence of amneziawg-go, asserted only in this
  repository's own prose.
- **UNVERIFIED:** byte-level proportion of surviving upstream code in
  `internal/masque`. Upstream is not in the local module cache.
- **UNVERIFIED:** contents of the 27 `.tar.gz` evidence bundles, which were not
  extracted.
- **UNVERIFIED:** whether any secret was ever committed and later removed.
  **This tree is not a git repository**, so no history scan was possible. This
  must be done against the real repository before publication.
- A second local account name, `winsvpn`, appears in gitignored build-output
  paths under `spikes/ios_maximum_privacy/PrivacyCore/.build/`. Weak evidence of
  a second developer machine, not of third-party authorship.
