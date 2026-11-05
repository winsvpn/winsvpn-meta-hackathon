# Winn Protocol v3 - Known Limitations and Open Questions

Measured against the tree at **2026-08-03T15:21:33Z**. See
[README.md](README.md) for measurement provenance.

This document is volunteered. Nothing in it was found by an auditor; all of it
was found by reading our own code. It is here because a package that only
describes strengths is not worth reading, and because anything listed here that
an auditor rediscovers is an hour they did not need to bill.

The ordering is by how much it should change an auditor's plan, not by
severity.

---

## 1. Maturity: what actually works today

### 1.1 One carrier completes a session, on one platform

**Only the `direct-awg` carrier completes a session end to end, and only on
Linux.**

| Carrier | Dials | Completes a session end to end |
|---|---|---|
| `direct-awg` | Yes, via `internal/directawg/udp.go` `UDPDialer` | **Yes, Linux only** |
| HTTP/3 and MASQUE | Yes, `carrier.H3Dialer` | Exercised against harnesses; **not proven as a user-facing session** |
| HTTP/2 | Yes, `carrier.H2Dialer` | Exercised against harnesses; **not proven as a user-facing session** |
| `reality-xhttp` | **No implementation** | No |
| `websocket-tls` | **No implementation** | No |
| `native-two-hop` | **No implementation** | No |
| `privacy-two-hop` | **No implementation** | No |

The four unimplemented names exist only in the contract enum
(`internal/connectivity/contract.go`) and are hard-refused with
`ErrCarrierUnimplemented` at `datapath/config.go`. They are named in
configuration surfaces, which makes them look supported. They are not.

Linux-only is structural, not incidental: `NewLinuxController` is
`//go:build linux`, and every other platform gets
`ErrLinuxControllerUnsupported` from
`internal/directawg/linux_constructor_unsupported.go`.

### 1.2 There is no single binary that connects

This is the most important structural fact in the package, and it is stated
here as well as in [02](02-ARCHITECTURE-AND-DATA-FLOW.md#41-a-structural-finding-first)
because an auditor who misses it will misjudge the maturity of everything else.

| Concern | Where it works | Where it does not |
|---|---|---|
| Rekey and PSK acquisition | `cmd/winn-client`, a shipping CLI | It does not discover a gateway, does not verify a manifest, and does not start a tunnel. Its endpoint and peer public key are **raw unverified command-line flags**. |
| Manifest verification, candidate racing, tunnel bring-up | `cmd/winn-auto-e2e`, `//go:build linux` | It is an end-to-end harness, not a shipping binary. |
| Cross-platform client facade | `clientbinding` | `TunnelSupported()` returns false on **every** target. `Connect` returns `ErrTunnelUnimplemented`. The package doc says so. |

A second consequence, easy to miss: `rotation.Coordinator.Rotate` is the only
function that performs the live rekey exchange, and it has **two non-test call
sites**, neither of which is on the connect path. The connect path calls only
`Coordinator.Pin`, which reads an already-applied PSK. **In the assembled flow,
rotation must have happened out of band beforehand.** Whether that is a
deployment assumption or a gap is an open question we would like answered.

### 1.3 Platform integrations compile; they do not run the protocol

`cdatapath` (C archive, iOS and macOS) and `cshared` (C shared library,
desktop FFI) compile and export a C ABI. They are exercised against test
harnesses. **Neither has been shown to carry a real session.** Both have
**zero test lines**. Both are excluded from `go build ./...` whenever
`CGO_ENABLED=0`, which is what `scripts/build_release.sh` and every scanner
run use, so **no automated gate in this repository compiles them at all**.

`datapath.PayloadIPPacket` returns `ErrPayloadUnimplemented`
(`datapath/config.go`). The datapath currently carries AWG datagrams, not raw
IP packets.

### 1.4 Code that landed during preparation of this package

Four other workstreams were editing this tree while this package was written.
Three changes landed inside the measurement window and are therefore
**unreviewed by anyone, including us**:

| Landed | What | Status |
|---|---|---|
| 2026-08-03 10:42 to 10:54 | Caller-supplied socket adoption for `H3Dialer` and `H2Dialer`, plus `datapath` descriptor adoption | Compiles, has tests, **no end-to-end proof on a real Android host** |
| 2026-08-03 11:15 | New `internal/revocation` package, 733 non-test lines, plus new `-device-revocation-list` flags on `cmd/winn-carrier-server` | **No review of any kind. Integration points UNVERIFIED.** |
| 2026-08-03 11:20 | `tlsconfig.ApplyCoverProfile`, an anti-active-probing TLS profile | Implemented, **zero callers**, permits TLS 1.2 on the cover path by design |
| 2026-08-03 after 11:30 | New `internal/connlimit` and `internal/decoy` packages | **Arrived too late to examine. Not described anywhere in this package.** |

An auditor should treat all of these as new code and price them accordingly. We
would rather say this than have a reviewer assume they carry the same maturity
as the surrounding packages.

**`internal/decoy` deserves a specific flag.** A package by that name is
self-evidently relevant to detectability, which is the top-ranked asset in the
threat model and the thing this project can least evaluate for itself. It
appeared in the last minutes of preparing this package and has had no review
here at all.

**Recommendation: freeze this tree before handing it to an auditor.** Over the
25 minutes spanning the final measurements, the tree gained three `internal/`
packages and roughly 2,300 lines. Scoping a paid engagement against a moving
tree produces findings against code that no longer exists, and the auditor
bills for the reconciliation.

---

## 2. Android

### 2.1 What the brief said, and what changed

Earlier internal statements said HTTP/2, HTTP/3 and MASQUE could not accept a
caller-supplied socket, and that this blocked Android. **That is no longer
accurate.** As of 2026-08-03 10:54 both carriers implement socket adoption,
with compile-time interface assertions at
`internal/carrier/supplied_socket.go`:

```go
var (
	_ PacketSocketDialer = (*H3Dialer)(nil)
	_ StreamSocketDialer = (*H2Dialer)(nil)
)
```

### 2.2 Android: the socket seam exists, the end-to-end proof does not

What is now true:

- `H3Dialer` adopts an unconnected `net.PacketConn` (UDP); `H2Dialer` adopts a
  connected, plaintext `net.Conn` (TCP).
- Adoption is fail-closed and single-use. A second dial returns
  `ErrSuppliedSocketConsumed`. The H2 path is a one-shot closure specifically
  so that `http.Transport`'s automatic re-dial **fails** rather than silently
  opening an unprotected replacement socket. That is the right failure mode for
  Android and is worth verifying independently.
- Endpoints on the supplied path must be IP literals, so no name resolution
  escapes the tunnel.
- `datapath` adopts raw descriptors via `os.NewFile` plus
  `net.FilePacketConn` / `net.FileConn`, entry point
  `datapath.OpenWithCarrier`.

What is still missing or unproven:

- **No end-to-end Android proof.** Nothing in this repository demonstrates a
  session established over a socket protected by `VpnService.protect(fd)`.
- **No `gomobile` invocation exists anywhere in the tree**, although
  `cshared/winn_clientbinding.go` states that Android and iOS use
  `gomobile bind`. How the mobile binding is actually produced is
  **UNVERIFIED**.
- `clientbinding.TunnelSupported()` still returns false on every platform, so
  the facade the host app would call still refuses.
- Server-side carriers (`H3Server`, `H2Server`) have no supplied-socket API.
  That is correct for the current design but worth confirming against the
  intended deployment.

**Open question for the engagement:** is the socket seam sufficient, or does
Android also need a protector callback on re-dial paths we have not enumerated?

---

## 3. Cryptographic design questions we cannot answer ourselves

### 3.1 The pre-shared key is transport-protected, not KEM-encapsulated

This is the design question we most want an outside opinion on.

The 32-byte AWG pre-shared key is generated by the controller's CSPRNG
(`internal/state/state.go`, `internal/state/postgres.go`) and sent to the device
as a base64 string in the `preshared_key` JSON field
(`internal/protocol/protocol.go`). It is covered by the ML-DSA response
signature, so it is **authentic**. It is not **independently confidential**.

Consequences:

- The PSK's post-quantum protection is exactly the post-quantum protection of
  the TLS 1.3 handshake, and nothing more.
- A break of the TLS channel, by any means, yields the PSK directly. There is
  no second layer.
- Internal naming calls this the "hybrid PSK"
  (`internal/rotation/coordinator.go`). That refers to the transport being
  hybrid. **The name invites exactly the misreading that produced the incorrect
  protocol description this package had to correct.** We consider the naming a
  defect in its own right.

**Questions:** should the PSK be independently KEM-encapsulated to the device's
long-term key? What would that cost in complexity, and does the hybrid TLS
channel already make it redundant? Is there a downgrade path where a weaker
channel is negotiated and the PSK is exposed?

### 3.2 The key ID is a bare hash of the secret

`key_id` is derived as `sha256(context || ... || psk)`
(`internal/protocol/protocol.go`) - a direct secret-into-hash construction
rather than an HMAC or a KDF. Preimage resistance makes this sound for a
32-byte uniform secret. It is not the conventional shape and we would like it
confirmed rather than assumed.

### 3.3 Domain separation relies on one mechanism, not two

`SignDomainMessage` builds `domain || 0x00 || message` across seven allow-listed
domains, but the ML-DSA `ctx` parameter is the **same fixed value**
(`"Winn-Protocol-v2"`) for every domain. Separation therefore rests entirely on
the prefix. We believe this is sufficient. We have not proved it.

### 3.4 Zeroization is best-effort and should not be claimed as more

Roughly 200 `clear()` call sites, plus a mutex-serialized idempotent
`Signer.Destroy()`. But `clear()` on a Go slice is not guaranteed against
compiler elision, the garbage collector may already have copied heap values,
and `circl`'s `NewKeyFromSeed` produces internal expansions that may persist.
**There is no `mlock` and no `madvise(MADV_DONTDUMP)` anywhere in the tree.**
Memory-scraping resistance should not be claimed to users.

### 3.5 The hybrid property itself is out of tree

The ML-KEM implementation, the X25519 implementation and the hybrid combiner
are all Go standard library. This repository contains no KEM arithmetic. That
is deliberate policy and it is defensible, but it means a crypto reviewer
auditing *this repository* cannot validate the hybrid property. They can
validate only that we enforce the right group and refuse fallbacks. We would
welcome an opinion on whether that delegation is the right call.

---

## 4. Specific implementation concerns

Ordered by how much they worry us.

### 4.1 `securefile` does not verify file ownership on Unix

`validatePrivatePath`, `securePrivatePath` and `validateOpenedPrivateFile` all
`return nil` on Unix (`internal/securefile/permissions_unix.go`). Real
ownership and ACL verification exists **only on Windows**
(`internal/securefile/permissions_windows.go`).

Every private-material read is therefore protected on Unix by a mode-bit check
alone. **A `0600` file owned by a different user, in a directory that user can
write, passes every check.** Whether that is reachable depends on the
deployment model, which is why it is listed as a concern rather than a finding.

### 4.2 The exec allow-list does not cover every exec boundary in its own package

`LinuxExecAllowList` documents its own limits candidly at
`internal/directawg/exec_allowlist.go`, and the documentation is accurate:

- It pins **path-name strings** by exact equality. No inode pinning, no content
  digest, no symlink resolution, no path normalisation.
- It is **per-runner, not per-process**.
- **Two exec boundaries in `internal/directawg` are not covered by it**:
  `execLinuxRunner` in `linux_exec.go`, which the default controller and policy
  paths use, and `runBoundedStatusCommand` in `status_cli.go`.

Additionally, `internal/awg/applier.go` execs the `awg` binary from a
command-line flag with only absolute/regular/executable validation, and
`os.Stat` follows symlinks. The only genuinely allow-listed production runner
is `internal/preparation/linux_underlay_runner_linux.go`, which uses a 2-entry
map and requires non-symlink regular executables.

An attacker who can write to `/opt/winn-lab/bin/` or swap a symlink target
defeats the weaker paths.

### 4.3 nftables health is checked by substring match

`internal/directawg/linux_policy.go`, `verifySetMembership`, verifies set
membership with `strings.Contains` on a quoted element rather than a structural
parse of `nft` output. This is the kill-switch health check. We are not
comfortable with it.

### 4.4 ECH rejection is never retried

The server marks ECH keys `SendAsRetry`, but **no client code catches
`tls.ECHRejectionError`** to re-drive the handshake with the server-supplied
retry configuration. Grep for `ECHRejectionError` and `RetryConfigList` returns
**zero hits tree-wide**. An ECH rejection surfaces as a plain handshake
failure.

Practical consequence: an ECH key rotation on the server, or any config
staleness, becomes a hard connection failure for the user rather than a
transparent retry. In the target environment a hard failure is a user who
cannot connect and does not know why.

### 4.5 `internal/carrier` is ECH-agnostic

`internal/carrier` never imports `echconfig`. A caller that forgets
`echconfig.ConfigureClient` gets a carrier with no ECH, and `internal/carrier`
will not object. Production is closed by a second gate in
`internal/h3candidate`, which refuses any production H3 dialer without a valid
ECHConfigList. That gate is load-bearing and deserves review, because it is the
only thing preventing a silent loss of the primary anti-blocking defence.

### 4.6 `internal/wcf3` is a complete unused wire format

A full second frame format with a 64-byte header, 1024-byte privacy cells and a
replay window exists, with three fuzz targets. Its `Encode` and `Decode` have
**no production callers**. Production uses WCF2. Either WCF3 should ship or it
should go; carrying an unused parser with a replay window is carrying risk for
no benefit. Flagged so an auditor does not spend hours reviewing a format that
never touches the wire.

### 4.7 `internal/pki` generates every key in the system and has zero tests

329 non-test lines, **0 test lines**. It generates the CA, server and device
ECDSA P-384 keys, the state key, the audit key, four ML-DSA seeds, the ECH
X25519 keys and the privacy-token RSA key.

### 4.8 `cmd/winn-carrier-server` has zero tests

576 non-test lines, 0 test lines, and it is one of only two production server
entry points.

### 4.9 Cover traffic and padding are unproven

The mechanisms exist: fixed-bucket length padding, a `CoverTrafficSender`
capability, a cover-traffic envelope kind. **We have no evidence that any of it
defeats any specific real-world DPI system.** No measurement against a
classifier exists in this repository. Given that detectability is the
top-ranked asset in the threat model, this is the largest gap between what the
code implies and what we can demonstrate.

Worse, the bucket set is fixed and small
(`{256, 512, 768, 1024, 1200, 1280, 1400, 1500, 1516}`). A padding scheme can
itself become the fingerprint. We would like this examined directly.

---

## 5. Testing and verification gaps

### 5.1 Fuzzing coverage is thin where it matters most

24 fuzz targets exist. **The release gate runs 9 of them, for 80 seconds
total.** The other 15 run only as seed-corpus unit tests under `go test`.

Not fuzzed at all, despite being on adversary-reachable or key-material paths:
`internal/state` state decoding, `internal/securefile`,
`internal/directawg` status parsing, `internal/awg` PSK readback parsing,
`datapath/duplex` frame decoding, and `datapath` config parsing.

Fuzzed but **not in the gate**: `internal/masque` proxy-request parsing,
`internal/gatewaymanifest` manifest decoding, and both `internal/echconfig`
targets. The manifest and ECH parsers are two of the highest-value targets in
the tree.

Seed corpus on disk is effectively empty: exactly one `testdata/fuzz` directory
exists (`internal/carrierauth/testdata/fuzz/FuzzSignatureHeader/`) and **it
contains zero seed files**. All seeding is in-code via `f.Add`. There is no
accumulated corpus, so each fuzz run starts near-cold.

### 5.2 There is no CI

No `.github/`, no `.gitlab-ci.yml`, no `.buildkite/`, no `.circleci/`, no
`.travis.yml`. Verified absent. The release gate is a shell script,
`scripts/verify.sh`, run manually. Nothing enforces that it runs before a
change lands.

Also: **this working tree is not a git repository.** There is no `.git`, so
there is no history, no authorship metadata, and no way to scan past commits
for secrets. A build artifact records `vcs.revision=6bf733e0...` and
`vcs.modified=true`, so a repository existed at build time. An auditor should
be given the actual repository, not this tree.

### 5.3 33 test functions cannot run without a build tag nothing passes

`winn_incomplete_e8` is the only custom build tag in the tree, used by 24 files
across `cmd/winn-local-sealed-node` and `cmd/winn-phase1-soak-controller`.
**No script anywhere passes it.** Consequently `go vet ./...` and
`go test -race ./...` in the release gate skip `cmd/winn-local-sealed-node`
entirely and skip 20 files of `cmd/winn-phase1-soak-controller`, and 33 test
functions never execute.

### 5.4 The gate runs on one platform, and skips silently

`scripts/verify.sh` runs on the host GOOS only. On a darwin runner, the three
Linux-only `cmd/` packages are never compiled or tested, and the entire
`//go:build linux` half of `internal/directawg` is never exercised. 81
Linux-gated test functions exist across 28 files.

Silent skips that will fire on a bare runner: 6 Postgres tests without
`WINN_POSTGRES_TEST_DSN`, OpenSSL interop tests without OpenSSL 3.5 or later,
C++ conformance tests without a toolchain, and a physical-Android-device gate.
The OpenSSL tests do re-check `WINN_RELEASE_GATE` and **fail rather than skip**
inside the gate, which is the right design.

One inverse hazard: `internal/auditcheckpoint/custody_test.go` **skips when
running as root**, because root ignores directory permissions. Running the
suite as root silently reduces coverage.

### 5.5 Two of the release build targets have no automated gate

`scripts/build_release.sh` sets `CGO_ENABLED=0`, and so does every scanner run.
`cdatapath` and `cshared` both `import "C"`. Therefore **neither is compiled by
the release script, by `go vet`, by `staticcheck`, by `gosec`, or by
`govulncheck`.** They are the FFI surface for iOS, macOS and desktop.

### 5.6 The build target list is duplicated and can drift

The shipping tuples are declared twice, in `scripts/build_release.sh` and in
`scripts/scanner_matrix_runner.sh`. They currently agree on all five tuples.
Nothing enforces that they continue to.

### 5.7 Prebuilt artifacts of unknown provenance are checked in

`tools/winn_conformance_build_out/` contains iOS and darwin `.a` archives and
android, darwin and windows binaries. **No script, Go generator, or document in
the tree produces them.** The exact `GOOS=ios GOARCH=arm64 -buildmode=c-archive`
command and SDK flags cannot be reconstructed from this repository. They are
**UNVERIFIED** and, in our view, should not ship.

### 5.8 The release gate does not currently pass

At the measurement snapshot, `gofmt -l .` reports `datapath/classify_test.go`
as unformatted, which `scripts/verify.sh` treats as a hard failure at step two.
`go vet ./...` and `go mod verify` both pass. This is almost certainly
transient churn from a concurrent workstream, but it is stated rather than
smoothed over: **as measured, the gate fails.**

---

## 6. Things we know we have not looked at

Listed so that silence is not mistaken for assurance.

- **`spikes/ios_maximum_privacy/`** is inside the same Go module, so
  `go test ./...` exercises its 5 Go packages, including a test that requires
  root. It contains its own HMAC-based construction that has had no review.
  Whether it should be in the module at all is an open question.
- **27 `.tar.gz` evidence bundles** under `evidence/` were not extracted or
  scanned.
- **The committed binaries** at the repository root and in `tools/` were not
  disassembled or scanned for embedded key material.
- **The three committed test-vector PSKs** (`testvectors/v2.json`) have no
  documented provenance. Nothing establishes them as synthetic. Locations only
  are recorded in [02](02-ARCHITECTURE-AND-DATA-FLOW.md#85-committed-secrets).
- **Runtime behaviour.** This entire package is a static reading. Nothing was
  built or executed beyond `go list`, `go vet`, `go mod verify` and `gofmt`.
- **`internal/revocation`**, which is nine minutes old at snapshot time.

---

## 7. Questions we would like the audit to answer

Compiled from the above, in the order we would spend money on them.

1. Can Winn traffic be distinguished from its cover protocol by a passive
   observer, at line rate, in any carrier? This is the top-ranked asset and the
   thing we can least evaluate ourselves.
2. Does the fixed padding bucket set become a fingerprint in its own right?
3. Should the PSK be independently KEM-encapsulated, or does the hybrid TLS
   channel make that redundant?
4. Is the manifest trust-state machine (rollback, equivocation, gap,
   predecessor digest, transparency inclusion) actually sound against a
   compelled operator?
5. Can the Linux kill switch be defeated by a failure ordering, a crafted `nft`
   output, or a subprocess that does not behave as parsed?
6. Is the supplied-socket path airtight enough to carry Android without leaking
   an unprotected socket on any re-dial or migration path?
7. Does the cover-profile split in `tlsconfig.ApplyCoverProfile` leak the strict
   path to an unauthenticated prober, and is permitting TLS 1.2 there safe?
8. Is delegating the entire hybrid key exchange to Go's standard library the
   right call for this threat model?
