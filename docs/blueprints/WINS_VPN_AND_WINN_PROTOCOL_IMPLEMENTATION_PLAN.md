# Win's VPN and Winn Protocol v3: Implementation Plan

**Repository:** `source/wins_vpn`
**Written:** 2026-08-03
**Measurement snapshot:** 2026-08-03T16:51:47Z, darwin/arm64 (Darwin 25.6.0), `go1.26.5 darwin/arm64`
**Companion:** [WINS_VPN_AND_WINN_PROTOCOL_BLUEPRINT.md](WINS_VPN_AND_WINN_PROTOCOL_BLUEPRINT.md)

This document answers "what is done, what is not, and in what order". The
blueprint answers "why is it shaped this way". Read that first if the
architecture is unfamiliar.

The honest gap list below is the most useful part of this document. Nothing here
is smoothed over. Where something could not be established it says **UNVERIFIED**.

---

## 0. Measurement method, and why the numbers will not match older documents

Every count below was produced by a command run on the measurement host, with
AppleDouble sidecars excluded (`! -name '._*'`). This working tree sits on a
volume that creates a `._<name>` sidecar for roughly 26,000 files. A naive
`find . -name '*.go'` overcounts by 526 files and a naive `grep -r` produces
hundreds of spurious binary matches. **Any tooling run against this working
tree, as opposed to a clean export, needs that filter.**

| Metric | Measured 2026-08-03T16:51Z | Stated in `docs/AUDIT_OUTREACH_DRAFTS.md:40-41` | Delta |
|---|---:|---:|---:|
| Directories containing Go files | **95** | 92 | +3 |
| `go list ./...` packages (darwin/arm64) | **91** | not stated | |
| Packages under `internal/` | **42** | 39 | +3 |
| Command packages under `cmd/` | **38** | not stated | |
| Non-test Go files | **333** | 325 | +8 |
| Non-test lines of Go | **112,237** | 108,674 | +3,563 |
| Test files | **244** | 226 | +18 |
| Test lines of Go | **87,553** | 82,998 | +4,555 |
| Fuzz targets | **24** | 24 | 0 |
| Direct module dependencies | **8** | not stated | |
| Indirect module dependencies | **6** | | |

**The commonly quoted "108,674 lines across 92 packages, 82,998 lines of tests,
7 direct dependencies" is stale on four of five figures.** The line counts drift
because the tree is under concurrent edit; the dependency count was simply wrong.
`go.mod` declares **8** direct requires: `cloudflare/circl`, `dunglas/httpsfv`,
`jackc/pgx/v5`, `quic-go/quic-go`, `yosida95/uritemplate/v3`, `golang.org/x/crypto`,
`golang.org/x/net`, `golang.org/x/sys`.

The drift is not noise. `winn_protocol_experimental/docs/audit/README.md:46-53`
records the tree gaining three `internal/` packages and about 2,300 lines inside
a single 25-minute window on 2026-08-03. **This tree should be frozen before it
is handed to an auditor.** Scoping a paid engagement against a tree that gains a
package every fifteen minutes produces findings against code that no longer
exists, and the auditor bills for the reconciliation.

Note also that the counts above include `spikes/`, which is inside the same Go
module and is therefore exercised by `go test ./...`. Excluding `spikes/` gives
90 directories, 104,406 non-test lines and 80,399 test lines. `spikes/` contains
its own unreviewed HMAC-based construction and a test that requires root.
Whether it should be in the module at all is an open question.

---

## 1. Current state per component

Status vocabulary: **Shipping** means it is in a released artifact.
**Proven** means a real command produced the claimed result and the evidence is
on disk. **Compiles** means it builds and has tests but has never carried real
traffic. **Absent** means there is no implementation.

### 1.1 Protocol engine, control plane

| Component | Status | Evidence |
|---|---|---|
| Hybrid PQ TLS 1.3 enforcement (single group, no fallback, post-handshake re-verification) | **Proven** | `internal/tlsconfig/tlsconfig.go` `validateState`, curve check at `:401-403`, completeness at `:404-406`; 464 non-test / 348 test lines |
| ML-DSA-65/87 signing and verification | **Proven** | `internal/pqauth`, circl v1.6.3 at `pqauth.go:17-18`; 688 non-test / 427 test lines; OpenSSL interop test present |
| Dual-family AND enforcement (mTLS identity plus ML-DSA payload) | **Proven** | `internal/carrierauth/auth.go:248-250` and `:277-279`; 773 non-test / 313 test lines |
| Rekey transaction, reconciliation latch, replay defence | **Proven** | `internal/bootstrap` 821/677 lines, `internal/rotation` 812/625 lines |
| Signed gateway manifest with rollback, equivocation, gap, predecessor-digest and transparency checks | **Proven** | `internal/gatewaymanifest/deployment_v2.go` `LoadVerifiedNodeV2`; 1,880 non-test / 997 test lines |
| Tamper-evident HMAC audit chain, server refuses to serve on unhealthy sink | **Proven** | `internal/audit` + `internal/auditcheckpoint`, 298 + 1,512 non-test lines |
| Anonymous carrier tokens (RSABSSA blind signatures, single-use ledger) | **Compiles / partially proven** | `internal/privacytoken` 888/326 lines; exercised in the carrier run at `~/.winn-e2e-lab/out/20260803T150537Z-carrier/` |
| Device revocation reaching the data plane | **Compiles, unreviewed** | `internal/revocation`, 733 non-test / 317 test lines, created 2026-08-03 11:15. **No review of any kind. Integration points UNVERIFIED.** |
| PKI: generates CA, server, device, state, audit, ML-DSA seed, ECH and privacy-token keys | **Compiles, untested** | `internal/pki`, **329 non-test lines and 0 test lines** |

### 1.2 Protocol engine, carrier plane

| Component | Status | Evidence |
|---|---|---|
| `H3Dialer` (HTTP/3 CONNECT-UDP, which is MASQUE) | **Compiles, exercised against harnesses** | `internal/carrier/h3.go:392`, `Dial` at `:519`; RFC 9298 via `internal/masque` |
| `H2Dialer` (HTTP/2 long-lived stream) | **Compiles, exercised against harnesses** | `internal/carrier/h2.go:333`, `Dial` at `:477` |
| `direct-awg` | **Proven end to end, Linux only** | `internal/directawg`; the only carrier with a completed user-shaped session |
| Caller-supplied socket adoption on both dialers | **Proven at unit level, no host caller** | Compile-time assertions at `internal/carrier/supplied_socket.go:161-164`; four mutation checks; real datagrams over real QUIC. **Nothing calls `datapath.OpenWithCarrier` from Kotlin, Swift or the WNN3 subprocess.** |
| Mandatory ECH, fail-closed, with a second independent gate | **Proven** | `internal/echconfig/ech.go:194-204, 223-233`; `internal/h3candidate/candidate.go:519-543` |
| WCF2 carrier framing, 16-byte header, duplicate suppression | **Proven** | `internal/carrier/envelope.go:400-457`; 4096-wide replay window at `server_envelope.go` |
| Length padding to fixed buckets, cover traffic | **Implemented, effectiveness unproven** | `envelope.go:95, 388-398`. See gap G1. |
| Path migration (RFC 9000) onto a supplied socket | **Compiles** | `internal/carrier/manager.go:187-207`; only `migratableH3PacketConn` implements `PathMigrator`; HTTP/2 returns an error by design |
| `reality-xhttp`, `websocket-tls`, `native-two-hop`, `privacy-two-hop` | **Absent** | Names in the contract enum only; hard-refused with `ErrCarrierUnimplemented` at `datapath/config.go` |
| `internal/wcf3`, a complete second wire format | **Absent from production** | 468 non-test / 328 test lines, three fuzz targets, **zero production callers of `Encode`/`Decode`**. WCF2 is on the wire. |
| `tlsconfig.ApplyCoverProfile`, anti-active-probing listener | **Implemented, zero callers** | Landed 2026-08-03 11:20. Permits TLS 1.2 on the cover path by design. Currently protects nothing. |
| `internal/connlimit`, `internal/decoy` | **Compiles, entirely unexamined** | Landed after 2026-08-03 11:30. Not described in the audit package. A package named `decoy` is directly relevant to the top-ranked asset. |

### 1.3 Portable datapath and platform bindings

| Component | Status | Evidence |
|---|---|---|
| `datapath` in-process package | **Proven** | Re-run at snapshot: `go test -count=1 ./datapath/... ./cmd/winn-datapath/` returns `ok` on all three packages (`datapath` 10.254s, `datapath/duplex` 1.169s, `cmd/winn-datapath` 6.041s). The owning lane records 69 passing tests. Builds `CGO_ENABLED=0` for all nine target pairs. |
| `cmd/winn-datapath` WNN3 subprocess entry point | **Proven, and a previously reported compile failure is fixed** | A conformance lane reported `undefined: duplex.Hello` at `main.go:168`. Re-verified 2026-08-03T16:51Z: `go build ./cmd/winn-datapath/` exits 0 and `go build ./...` over the whole module exits 0. `duplex.Hello` no longer exists or is referenced. |
| WNN3 framing, byte-identical across Go and C++ | **Proven** | A Go test compiles `windows/runner/winn_frame.h` and diffs 9 golden vectors; `clang++ -std=c++17` against the same header prints matching constants |
| `cdatapath` C archive (iOS, macOS) | **Compiles, never gated** | `xcrun nm -gU` lists all 9 `_WinnTunnel*` symbols; a C program linked against `libwinn_datapath.a` moved 200 and 300 bytes both ways with `transport_observed_both_ways=true`. **Zero test lines. Excluded from every automated gate because they set `CGO_ENABLED=0`.** |
| `cshared` C shared library (desktop FFI) | **Compiles, never gated** | Same exclusion. Zero test lines. |
| `clientbinding` cross-platform facade | **Deliberately refusing** | `TunnelSupported()` returns false on **every** target (`binding.go:62`); `Connect` returns `ErrTunnelUnimplemented` (`binding.go:203`). The package doc says so. Re-run at snapshot: `go test -count=1 ./clientbinding/` returns `ok` in 0.222s. |

### 1.4 Platform hosts (the application repository)

State as recorded in `WINN_PROTOCOL_PLATFORM_PLAN.md` LIVE PROGRESS, synced
2026-08-03T15:11:19Z, cross-checked by an independent conformance lane.

| Lane | Status | What is real | What is not |
|---|---|---|---|
| `datapath` | done, 9/9 | Portable datapath, C archive, WNN3 subprocess, all nine build targets with recorded `file(1)` output | See 1.3 |
| `android` | done, 8/8 | 5 new Kotlin files plus additive wiring in `VpnTunnelService.kt`; protected-socket-before-spawn enforced and proven by two mutation checks; `:app:testDebugUnitTest` 40/40; `assembleDebug` succeeds | Integrated **against a JVM test double**, not the Go engine. `libwinnengine.so` deliberately **not staged**: the debug APK contains only `libxray.so` for both ABIs, independently confirmed by `unzip -l`. Release variant compile **UNVERIFIED**, blocked by the repo's own signing guard. |
| `apple` | done, 7/7 | ObjC wrapper and C header alongside the AWG wrapper; five C ABI symbols exported; `swiftc -typecheck` of both providers exits 0; full-chain loader harness passes 15 checks; the real wrapper dylib stages into a valid framework | Everything below the `WinnTunnel*` C boundary is **against an in-process loopback double**. `WinnTunnel.h` is marked PROVISIONAL. **No on-device or simulator run, no real tunnel, no `xcodebuild` of the PacketTunnel target.** |
| `windows` | **BLOCKED, 8/9** | Host implemented; compiles under `/W4 /WX` on real MSVC 14.51.36231 and links to `wins_vpn_tunnel_service.exe`; C++ to Go round trip passes over a real Windows anonymous pipe against the real cross-compiled engine | **Windows arm64 is unbuildable here for two independent reasons.** See B1. WinTun adapter creation, address/MTU/DNS assignment, route promotion and the packet pumps have **never been executed**. |
| `conformance` | done, 7/7 | `tools/winn_conformance_verify.py`, 9 subcommands, all running real subprocesses or real archive reads; guard test `test/winn_protocol_refusal_guard_test.dart` | Found two real regressions in a shared build script, since fixed by the owning lane |

**Baselines that must not regress**, measured 2026-08-03:
`flutter analyze` returns `No issues found!`; `flutter test` returns **341
passing, 0 failing** (336 pre-existing plus 5 from the refusal guard);
`go test ./clientbinding/` returns ok. Do not "fix" the 341 by deleting the
guard file: it is the test that stops anyone advertising Winn support that does
not exist.

### 1.5 Shipping application

| Component | Status | Evidence |
|---|---|---|
| Flutter client `org.winsvpn.app` `1.0.14+29` | **Shipping, in review at three stores** | `pubspec.yaml:5`; Android id at `android/app/build.gradle.kts:38` |
| AmneziaWG tunnel on Android, iOS, macOS, Windows | **Shipping** | Provider inventory in the blueprint, section 7.2 |
| Winn Protocol in the application | **Refused by design** | `winn/3` refusal in `lib/main.dart`, guarded by `test/winn_protocol_refusal_guard_test.dart` |
| Security remediation backlog (H-1 to H-6, M-1 to M-6, L-1) | **All code-level items done** | `FINAL_RECOMMENDATIONS_FIX_HANDOFF_20260722.md`. **H-2 stays OPEN and is not closable by code**: the owner must rotate and revoke the fleet-wide `ADMIN_TOKEN` and verify every host rejects it. |
| Play Store screenshot rejection (twice) | **Owner action required in Play Console** | `PLAY_STORE_REMEDIATION_20260803.md`: of 9 images, keep 4, remove 2, replace 3. Highest priority removal is image 7, which shows a competitor's trademark. Nothing in the repository can change this. |
| Decoy calculator redesign | **Pending owner input** | Does not match either real OS calculator; TI-84 look explicitly rejected |

### 1.6 Evidence that exists on disk

| Evidence | Location | What it proves |
|---|---|---|
| Real two-endpoint session | `~/.winn-e2e-lab/` | Completed AWG handshake (`last_handshake_time` 1785769383 on both sides), 4 MiB each way with cross-matching sha256 (`payload-client.sha256` equals `received-gateway.sha256`, and the mirror), counters conserved with `rx_dropped=0` and `transport_observed_both_ways=true`, plus a **negative control**: 500 off-path datagrams with a forged `h4` leading word moved `rx_foreign_sender` to exactly 500 and moved no transport counter. Canonical run `out/20260803T150054Z-awg/`. A separate Winn PQ carrier run at `out/20260803T150537Z-carrier/` returns `PASS` and `audit verify: exit 0`. |
| What that session does **not** prove | `~/.winn-e2e-lab/AUDIT_EVIDENCE.md:279-295` | No Android, iOS, macOS or Windows. Runs A and B are **separate stacks**. Both endpoints are containers on one physical machine under x86-64 emulation. `handshake_response_observed` is structurally always false under obfuscation. |
| Fugu Ultra adversarial review | `docs/reviews/fugu-ultra-adversarial-20260803/FINDINGS.md` (**app repo, not the protocol repo**) | 10 findings claimed, **9 confirmed, 1 rejected**; 4 HIGH, 3 MEDIUM, 3 LOW; **34 of 34 citations exact** against the prior review's 1 of 17. Verdict: "the cryptography is conservative and well built; the wire behaviour is conspicuous." Coverage was 10 files across 6 packages; `masque`, `directawg`, `privacytoken` internals, `wcf3`, `pki`, `identity`, `state`, `rotation`, `gatewaymanifest`, `transparency` and all of `cmd/` were **not reviewed**. |
| Server readiness review | `winn_protocol_experimental/docs/reviews/server-readiness-20260803/SERVER_READINESS_REVIEW.md` | Marked NON-AUTHORITATIVE. Verdict: **not production ready**. Three blockers: probe resistance, revocation never reaching the carrier data plane, plaintext `device_id` in Postgres. Four High, two Medium, one Low. One fix landed in-review: peer-IP log redaction, 3000 raw `IP:port` lines to 0. |
| Fuzz hardening review | `winn_protocol_experimental/docs/reviews/fuzz-hardening-20260803/` | 11 targets to 24; one crasher found and fixed; `govulncheck` clean |
| Audit readiness package | `winn_protocol_experimental/docs/audit/` | Eight documents for OTF and OSTIF outreach |
| Conformance baselines | `tools/winn_conformance_results/` | `baseline_first_pass.json`, `baseline_final_pass.json`, `baseline_final_pass2.json` |

---

## 2. The honest gap list

Ordered by how much it should change a reader's plan.

### G0. There is no single binary that connects

**This is the most important structural fact about the protocol and it should be
read before anything else.** No production binary performs the complete sequence
from "user clicks connect" to "encrypted traffic flows"
(`docs/audit/02-ARCHITECTURE-AND-DATA-FLOW.md:235-249`).

* `cmd/winn-client` is a shipping CLI that does rekey and PSK acquisition. It
  does not discover a gateway, does not verify a manifest, and does not start a
  tunnel. Its endpoint and peer public key are **raw unverified command-line
  flags**.
* `cmd/winn-auto-e2e` does manifest verification, candidate racing and tunnel
  bring-up. It is `//go:build linux` and is a harness, not a shipping binary.
* `clientbinding` is the cross-platform facade and it refuses on every target.

A related and easily missed consequence: `rotation.Coordinator.Rotate`, the only
function that performs the live rekey exchange, has **two non-test call sites,
neither on the connect path**. The connect path calls only `Coordinator.Pin`,
which reads an already-applied PSK. In the assembled flow, rotation must have
happened out of band beforehand. Whether that is a deployment assumption or a
gap is an open question.

### G1. Cover traffic and padding are unproven, and this is the top asset

The mechanisms exist: fixed-bucket length padding, a `CoverTrafficSender`
capability, a cover-traffic envelope kind. **No measurement against any
classifier exists in this repository.** Given that detectability is the
top-ranked asset in the threat model, this is the largest gap between what the
code implies and what can be demonstrated.

Worse, the bucket set is fixed and small
(`{256, 512, 768, 1024, 1200, 1280, 1400, 1500, 1516}`). A padding scheme can
itself become the fingerprint.

Measured cost of enabling padding, from the 2026-08-03 work: **+2.8% on bulk
traffic, +35.3% on mixed**. Padding was also a **partial no-op when enabled**
before that fix, in that full-size traffic was unpadded.

### G2. The pre-shared key is transport-protected, not KEM-encapsulated

The 32-byte AWG PSK is generated by the controller's CSPRNG
(`internal/state/state.go`, `internal/state/postgres.go`) and sent to the device
as a base64 string in the `preshared_key` JSON field. The ML-DSA response
signature covers it, so it is **authentic**. It is not **independently
confidential**. Its post-quantum protection is exactly the post-quantum
protection of the TLS 1.3 handshake and nothing more; a break of the TLS channel
yields the PSK directly, with no second layer.

Internal naming calls this the "hybrid PSK", which refers to the transport being
hybrid. **That name invited exactly the misreading that produced the incorrect
protocol description this project had to correct.** The naming is a defect in
its own right.

### G3. Only one carrier completes a session, and only on Linux

`direct-awg` is the only carrier with a proven end-to-end user-shaped session,
and `NewLinuxController` is `//go:build linux`. Every other platform gets
`ErrLinuxControllerUnsupported`. The h2 and h3 carriers have been exercised
against harnesses; neither has been proven as a user-facing session.

### G4. The FFI surface is compiled by no automated gate

`scripts/build_release.sh` sets `CGO_ENABLED=0`, and so does every scanner run.
`cdatapath` and `cshared` both `import "C"`. Therefore neither is compiled by
the release script, by `go vet`, by `staticcheck`, by `gosec`, or by
`govulncheck`. They are the FFI surface for iOS, macOS and desktop, and they
have **zero test lines between them**.

### G5. There is no CI, and this tree is not a git repository

No `.github/`, no `.gitlab-ci.yml`, no `.buildkite/`, no `.circleci/`, no
`.travis.yml`. Verified absent. The release gate is `scripts/verify.sh`, run
manually, with nothing enforcing that it runs before a change lands.

There is no `.git` in `winn_protocol_experimental/`, so there is no history, no
authorship metadata, and no way to scan past commits for secrets. A build
artifact records `vcs.revision=6bf733e0...` and `vcs.modified=true`, so a
repository existed at build time. **An auditor should be given the actual
repository, not this tree.**

### G6. Test coverage has specific, named holes

* **33 test functions cannot run.** `winn_incomplete_e8` is the only custom build
  tag in the tree, used by 24 files, and **no script anywhere passes it**.
* **The gate runs on one platform.** On a darwin runner the three Linux-only
  `cmd/` packages are never compiled or tested and the entire `//go:build linux`
  half of `internal/directawg` is never exercised. 81 Linux-gated test functions
  exist across 28 files.
* **Fuzzing is thin where it matters.** 24 targets exist; the release gate runs
  **9 of them for 80 seconds total**. Not fuzzed at all, despite being on
  adversary-reachable or key-material paths: `internal/state` decoding,
  `internal/securefile`, `internal/directawg` status parsing, `internal/awg` PSK
  readback, `datapath/duplex` frame decoding, `datapath` config parsing. Fuzzed
  but not in the gate: `internal/masque` proxy-request parsing,
  `internal/gatewaymanifest` decoding, and both `internal/echconfig` targets.
  Exactly one `testdata/fuzz` directory exists and **it contains zero seed
  files**, so every run starts near-cold.
* **One inverse hazard.** `internal/auditcheckpoint/custody_test.go` skips when
  running as root. Running the suite as root silently reduces coverage.

### G7. Named implementation concerns, in the order they worry us

1. **`securefile` does not verify file ownership on Unix.** The three helpers
   that would do so all `return nil` on Unix. Real ownership and ACL
   verification exists **only on Windows**. A `0600` file owned by a different
   user, in a directory that user can write, passes every check.
2. **The exec allow-list does not cover every exec boundary in its own
   package.** It pins path-name strings by exact equality with no inode pinning,
   no content digest, no symlink resolution. Two exec boundaries in
   `internal/directawg` are not covered by it. `internal/awg/applier.go` execs a
   binary from a command-line flag with only absolute, regular and executable
   validation, and `os.Stat` follows symlinks.
3. **nftables health is checked by substring match.** `verifySetMembership` uses
   `strings.Contains` on a quoted element rather than a structural parse. This is
   the kill-switch health check.
4. **ECH rejection is never retried.** The server marks keys `SendAsRetry`, but
   grep for `ECHRejectionError` and `RetryConfigList` returns **zero hits
   tree-wide**. An ECH key rotation on the server becomes a hard connection
   failure for the user rather than a transparent retry. In the target
   environment that is a user who cannot connect and does not know why.
5. **`internal/carrier` is ECH-agnostic.** A caller that forgets
   `echconfig.ConfigureClient` gets a carrier with no ECH and `internal/carrier`
   will not object. Production is closed by a second gate in
   `internal/h3candidate`, which is therefore load-bearing.
6. **Zeroization is best-effort.** Roughly 200 `clear()` sites plus a
   mutex-serialized `Signer.Destroy()`, but `clear()` on a Go slice is not
   guaranteed against compiler elision, the GC may already have copied heap
   values, and there is **no `mlock` and no `madvise(MADV_DONTDUMP)` anywhere**.
   Memory-scraping resistance must not be claimed to users.

### G8. Artifacts of unknown provenance are checked in

`tools/winn_conformance_build_out/` contains iOS and darwin `.a` archives and
android, darwin and windows binaries. **No script, Go generator or document in
the tree produces them.** The exact `GOOS=ios GOARCH=arm64 -buildmode=c-archive`
command and SDK flags cannot be reconstructed. They are UNVERIFIED and should
not ship. Nine root-level executables and 27 `.tar.gz` evidence bundles are
likewise tracked; `winn-datapath` records `vcs.modified=true`, meaning it was
built from a dirty tree, which alone disqualifies it from a reproducible release.

### G9. Documentation drift that will cost auditor hours

* `README.md` and `SPECIFICATION.md` are titled "Winn Protocol v2"; the project
  is v3. Both version constants are correct (see the blueprint, section 4.2), but
  a reader must be told.
* `THREAT_MODEL.md` at the tree root is the v2 document; the current one is
  `docs/audit/01-THREAT-MODEL.md`.
* `docs/AUDIT_OUTREACH_DRAFTS.md:40-41` carries stale counts.
* Fugu review citations no longer resolve by line number, though every symbol
  name is still correct.
* `.winn_platform_progress/datapath.json` was still reading "step 2/7, mapping in
  progress" while the datapath lane had in fact delivered substantially. That is
  the opposite of fabrication, but two other lanes were waiting on a handoff
  signal that the file gave no sign had happened.

### G10. Release-gate state, and one correction to an earlier report

The audit package recorded, at snapshot 15:21Z, that `gofmt -l .` flagged
`datapath/classify_test.go`, which `scripts/verify.sh` treats as a hard failure
at step two, so **as measured then, the gate failed**.

**Re-measured at 2026-08-03T16:51:47Z: `gofmt -l .` is clean, `go build ./...`
exits 0, and `go build ./cmd/winn-datapath/` exits 0.** The transient churn
cleared and the two build-script regressions the conformance lane found have
been fixed by the owning lane (`select_clientinfo_archive` and
`require_archive_selection` are present in
`tools/build_winn_protocol_engine.sh`). The full `scripts/verify.sh` gate was
**not** run as part of this document, so its overall pass state is **UNVERIFIED**.

---

## 3. Ordered remaining work

Dependencies are stated explicitly. Nothing below is a calendar estimate.

### Phase A. Freeze and hand over (blocks the audit engagement)

| # | Work | Depends on | Blocked by |
|---|---|---|---|
| A1 | **Freeze the tree** at a commit and hand the auditor a real git repository, not this working copy | Nothing | Nothing. This is the highest-value action available. |
| A2 | Re-run the measurement commands in `05-BUILD-AND-REPRODUCTION.md` section 8 against the frozen commit and reconcile against the audit package | A1 | Nothing |
| A3 | Deliver the **out-of-band trust-root fingerprint** | Nothing | **Owner only.** Open decision 10.4-1. Blocks R15. |
| A4 | Remove committed binaries and extend `.gitignore`; do not ship `tools/winn_conformance_build_out/` | A1 | Nothing |
| A5 | Confirm provenance of the three `testvectors/v2.json` PSKs and run a secret scan against the real git history | A1 | Nothing. Cannot be done against this tree, which has no `.git`. |
| A6 | Reconcile the v2/v3 documentation drift (G9) | Nothing | Nothing |

### Phase B. Release blockers for the protocol

| # | Work | Depends on | Blocked by |
|---|---|---|---|
| B1 | **Cover certificate.** Without `-cover-cert` every prober reads the Winn CA issuer | Nothing | Open decision 10.4-2. Named a **release blocker**. |
| B2 | Wire `tlsconfig.ApplyCoverProfile`, which currently has zero callers, and get the cover/strict split reviewed | B1 | The split is unreviewed; permitting TLS 1.2 on the cover path needs a second opinion |
| B3 | Apply the cover profile in `winn-server` and `winn-token-issuer`, which never do; only the carrier server does | B1, B2 | Open decision 10.4-3 |
| B4 | **uTLS-equivalent ClientHello mimicry.** The server now looks ordinary; the client is still trivially fingerprintable on its first flight | Nothing | Open decision 10.4-4. Recorded as **the highest-value remaining protocol work.** |
| B5 | Close the three server-readiness blockers: probe resistance, revocation reaching the carrier data plane, plaintext `device_id` in Postgres | B1 for the first | Server readiness review, which is NON-AUTHORITATIVE and needs an authoritative successor |
| B6 | Review `internal/revocation`, `internal/connlimit` and `internal/decoy`, none of which has had any review | Nothing | Needs a family-distinct reviewer |

### Phase C. Make one binary connect (G0)

| # | Work | Depends on | Blocked by |
|---|---|---|---|
| C1 | Decide whether `rotation.Coordinator.Rotate` being off the connect path is a deployment assumption or a gap | Nothing | Needs a design answer, not code |
| C2 | Join the two halves: manifest verification plus candidate racing plus bring-up, in a shipping binary rather than a Linux-only harness | C1 | Nothing technical. This is the single largest engineering item. |
| C3 | Make `clientbinding.TunnelSupported()` capable of returning true on at least one target | C2 | C2 |
| C4 | Add ECH rejection retry (`ECHRejectionError`, `RetryConfigList`), currently zero hits tree-wide | Nothing | Nothing. Small, and it converts a hard user-facing failure into a transparent retry. |

### Phase D. Platform hosts, from double to real engine

Each lane is currently integrated against a test double. The work is to replace
the double with the real engine and then to run it.

| # | Work | Depends on | Blocked by |
|---|---|---|---|
| D1 | Diff the real `_cgo_export.h` against the PROVISIONAL `apple/EngineWrappers/WinnTunnel.h` and confirm the two documented assumptions (non-blocking `ReadOutbound` returning 0; heap buffer ownership for `StatusJSON`) | 1.3 c-archive | Nothing |
| D2 | Stage `libwinnengine.so` on Android and run against the real Go engine rather than `WinnEngineDouble` | Nothing technical | **`1.0.14+29` is in store review.** Staging is deliberately deferred; `android/tools/prepare_android_winn_assets.sh --stage` is the one line that would do it. |
| D3 | Prove an Android session over a socket protected by `VpnService.protect(fd)` end to end | D2 | Nothing in this repository demonstrates this today |
| D4 | Wire a host caller for `datapath.OpenWithCarrier` so Android gets an h2 or h3 carrier rather than `direct-awg` | C2 | The C ABI cannot reach it, because it needs a Go dialer. This is an API-shape decision. |
| D5 | Execute the Windows path on a box with admin and the WinTun driver: adapter creation, address/MTU/DNS, route promotion, packet pumps | Nothing | **Never executed.** Compiles and links only. |
| D6 | Tighten the Windows route-promotion gate from "create-acknowledged and `up:true`" to `transport_observed_both_ways AND hostAWG.latestHandshake is recent` | D5 | Called out in-code at the promotion site. **Must be tightened before Winn carries user traffic.** |
| D7 | Windows arm64 | Owner action | **BLOCKED on the toolset, not on Flutter.** The build box has no `HostX64\arm64` MSVC toolset; `vcvarsall x64_arm64` silently falls back to the x64 compiler and then fails at link with LNK1104. Related pre-existing gap: the AmneziaWG side is x64-only too. ~~Flutter 3.44.8 exposes no `windows-arm64` target platform at all.~~ **Retracted 2026-08-06 — that claim was false and had blocked a toolchain decision.** Verified against the 3.44.8 checkout (`058e0af2c2b57e369d905a03ac9748b0ebf543c6`): `TargetPlatform.windows_arm64` is declared at `packages/flutter_tools/lib/src/build_info.dart:631` with both-direction name mapping at `:846`/`:872`; `windows/build_windows.dart:175` maps it to CMake arch `ARM64` on the real build path; and `commands/build_windows.dart:67-68` **auto-selects** `windows-arm64` when the host is ARM64 Windows — which is why the Yoga's plain `flutter build windows --release`, with no platform flag, still produces `build\windows\arm64\`. All five windows-arm64 engine artifacts for engine `0cd610717bde95fd88343c64f81c11ba4e5c0010` are published and fetch HTTP 200 at real sizes (release 66,090,323 B; debug 81,323,470 B; profile 68,068,573 B). The claim most likely arose because `flutter build windows` has **no** `--target-platform` flag on any version — the target is derived from the host — so passing one fails with `Could not find an option named "--target-platform"`, which reads like the platform is missing. Evidence: `docs/handoff/TOOLCHAIN_CONVERGENCE_AND_APPLE_GATE_PROVISIONING_20260806.md` §4 and `tools/toolchain-pins.json` under `pending_convergence.blocker_status`. |
| D8 | Run the Apple PacketTunnel target on device or simulator | Signing | No `xcodebuild` of the PacketTunnel target has been done |
| D9 | Add a gate that can tell the Apple test double from a real archive; both export the same five symbols | D1 | Currently build-input discipline only, enforced by no gate |

### Phase E. Application

| # | Work | Depends on | Blocked by |
|---|---|---|---|
| E1 | **Rotate and revoke the fleet-wide `ADMIN_TOKEN`** and verify every host rejects it | Nothing | **Owner only.** H-2 has been open since 2026-07-22 and is not closable by code. |
| E2 | Action the Play Store screenshot remediation in Play Console | Nothing | **Owner only.** Nothing in the repository can change store assets. |
| E3 | Decoy calculator redesign | Owner choice of Samsung or iOS look | Pending owner input |
| E4 | Do not flip the `winn/3` refusal | Everything above | **Governance decision, explicitly not an engineering one.** |

### Phase F. Legal and licensing

| # | Work | Depends on | Blocked by |
|---|---|---|---|
| F1 | Counsel review of AI-authorship exposure | Nothing | **Blocking for the commercial licence.** Open decision 10.4-7. A CLA cannot fix it, because the question is whether copyright subsists at all. |
| F2 | Add SPDX headers to the five upstream-derived `internal/masque` files | Nothing | Blocking |
| F3 | Capture the `amneziawg-go` LICENSE and pin the upstream commit for `patches/amneziawg-go-fast-handshake-v1.patch` | Nothing | Blocking. The upstream licence is currently asserted only in this repository's own prose, and is UNVERIFIED. |
| F4 | Counsel review of GPL-2.0 tooling distribution (`amneziawg-tools`, `ip`, `nft`, `resolvectl`) before any image ships | Nothing | Blocking for images |
| F5 | Decide whether `spikes/ios_maximum_privacy/` ships at all | Nothing | Not blocking, but it is in the Go module and carries an unreviewed HMAC construction |

---

## 4. Open decisions from handoff section 10.4, mapped to what they block

| # | Decision | Owner | Blocks |
|---|---|---|---|
| 1 | Out-of-band trust-root fingerprint delivery | **Owner only** | A3, and the R15 review chain |
| 2 | Cover certificate (`-cover-cert`) | Owner | B1, and transitively B2, B3, B5. **Release blocker.** |
| 3 | `winn-server` and `winn-token-issuer` never apply the cover profile | Owner or lead | B3 |
| 4 | No uTLS-equivalent ClientHello mimicry | Lead | B4. Highest-value remaining protocol work, and it targets gap G1 and asset S1 directly. |
| 5 | AIAV needs post-week-63 data | Owner | Nothing in this repository. Belongs to Win For All. |
| 6 | Psych r16 remains DO-NOT-SHIP | **Owner only** | Nothing in this repository. Belongs to Win For All. |
| 7 | AI-generated authorship and whether copyright subsists | **Counsel** | F1, and the entire commercial half of the dual licence |
| 8 | Tier 3 automation: `REVIEW_TIERING_20260802.md:68` says "Not automatable from Claude Code", yet both of 2026-08-03's reviews were driven programmatically with Claude as transport | Governance | B6 and any review that must be family-distinct. **Read strictly, both of those reviews are rehearsals.** |

Two further open items predate section 10 and are still open:

* **Gate 6 evidence integrity.** The closure claim needs a caveat: the
  supporting batch predates the `force_carrier` fix, is 100 per class rather than
  1,000, and is anchorless. Separately, an accounting invariant that failed was
  weakened from exact equality to a one-sided bound, so **the exact failure
  pattern would now pass silently.** Not resolved.
* **Throughput bottleneck.** `RelayLocalUDP` does unbatched one-packet-at-a-time
  syscalls, 160,000+ blocking syscalls per second. Four options ranked by trust
  and portability impact; batching with `golang.org/x/net/ipv4`/`ipv6`
  `ReadBatch`/`WriteBatch` is the recommended starting point and the dependency
  is already present. Needs owner direction: it is an architectural and
  trust-model tradeoff, not a performance tweak.

---

## 5. What an auditor should be asked to answer

Reproduced from `docs/audit/04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md:437-457`
because it is the right prioritisation and should not be restated differently
here.

1. Can Winn traffic be distinguished from its cover protocol by a passive
   observer, at line rate, in any carrier?
2. Does the fixed padding bucket set become a fingerprint in its own right?
3. Should the PSK be independently KEM-encapsulated, or does the hybrid TLS
   channel make that redundant?
4. Is the manifest trust-state machine sound against a compelled operator?
5. Can the Linux kill switch be defeated by a failure ordering, a crafted `nft`
   output, or a subprocess that does not behave as parsed?
6. Is the supplied-socket path airtight enough to carry Android without leaking
   an unprotected socket on any re-dial or migration path?
7. Does the cover-profile split leak the strict path to an unauthenticated
   prober, and is permitting TLS 1.2 there safe?
8. Is delegating the entire hybrid key exchange to Go's standard library the
   right call for this threat model?

---

## 6. Reproducing every number in this document

```sh
cd winn_protocol_experimental

# Toolchain and module health
go mod verify                 # expect: all modules verified
go mod tidy -diff             # expect: exit 0, no diff
go build ./...                # expect: silence, exit 0
gofmt -l . | grep -v '^\._'   # expect: no output

# Counts (the ._* filter is mandatory on this volume)
find . -name '*.go' ! -name '._*' | sed 's|/[^/]*$||' | sort -u | wc -l
ls -1 internal/ | grep -v '^\._' | wc -l
find . -name '*.go' ! -name '._*' ! -name '*_test.go' -exec cat {} + | wc -l
find . -name '*_test.go' ! -name '._*' -exec cat {} + | wc -l
grep -rn '^func Fuzz' --include='*.go' . | grep -v '/\._' | wc -l
go list ./... | wc -l

# Cross-compilation, all five release tuples
for t in linux/amd64 linux/arm64 darwin/arm64 windows/amd64 android/arm64; do
  os=${t%/*}; arch=${t#*/}
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -mod=readonly -trimpath \
    -buildvcs=false -o /dev/null ./cmd/winn-client \
    && echo "OK   $t" || echo "FAIL $t"
done

# Datapath and binding
go test -count=1 ./datapath/... ./cmd/winn-datapath/
go test -count=1 ./clientbinding/
```

From the application repository root: `flutter analyze` (expect
`No issues found!`), `flutter test` (expect 341 passing), and
`python3 tools/winn_conformance_verify.py all`.

**One trap.** `go mod download all` will fail on missing sums. Nine modules in
`go list -m all` have no `go.sum` entry because they are test or tool
dependencies of dependencies that are never built here. That is correct
behaviour under module-graph pruning, not a defect. Use `go mod download`
without `all`, or just `go mod verify`.
