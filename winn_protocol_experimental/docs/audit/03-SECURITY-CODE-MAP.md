# Winn Protocol v3 - Security-Relevant Code Map

Measured against the tree at **2026-08-03T15:21:33Z**. See
[README.md](README.md) for measurement provenance.

**Purpose.** 93 directories contain Go code. Most of them are harnesses,
evidence tooling, or plumbing. This document says which ones handle
attacker-controlled input or key material, ranked by exposure, so that review
hours land where findings are.

**Line counts** below are non-test lines and test lines for that directory
only, not including subdirectories.

> **Read line numbers as snapshot-relative.** This tree was under concurrent
> edit by four other workstreams while this package was written, and line
> numbers moved measurably during the writing of it. **The durable anchor is
> the file path plus the symbol name; the line number is a convenience.** If a
> cited line does not contain what this document says, grep for the named
> symbol in the named file before concluding the document is wrong. See
> [README.md](README.md#the-tree-moves).

---

## Summary: where to spend the budget

| Tier | What it is | Directories | Non-test lines | Share of tree |
|---|---|---|---|---|
| **0** | Parses raw bytes an adversary fully controls, or performs cryptography | 9 | 10,033 | 9.0% |
| **1** | Parses signed or authenticated input; holds or persists key material | 13 | 12,352 | 11.1% |
| **2** | Subprocess and OS boundary; privileged system state | 5 | 18,473 | 16.6% |
| **3** | Host-application boundary; trusted caller, untrusted bytes | 6 | 2,894 | 2.6% |
| **4** | Orchestration and policy logic with security consequences | 11 | 11,948 | 10.7% |
| **5** | Harnesses, evidence tooling, fixtures, plumbing | 49 | 55,579 | 49.9% |
| | **Total** | **93** | **111,279** | |

**If an auditor reads only tiers 0 and 1, they cover 22,385 lines, 20% of the
tree across 22 directories, and every place a remote adversary's bytes are
first interpreted or a secret is handled.** Tier 5 is half the code and is
where an unguided engagement would lose its budget.

Tier 2 is larger than tier 0 and tier 1 combined. That is not an accident of
counting: the Linux session bring-up, its firewall and DNS policy, and the
candidate-racing machinery genuinely are the bulk of the security-relevant
implementation, and they are the part most likely to contain an exploitable
leak. Do not skip it because it is not cryptography.

---

## Tier 0: Adversary-controlled bytes and cryptography

These parse data that a network adversary chooses freely, before any signature
or authentication has been checked, or they implement cryptographic operations.
A memory-safety or logic bug here is directly reachable.

### 0.1 `internal/carrier` - 5,242 non-test / 4,290 test lines

The carrier envelope codec and both carrier implementations. Highest-value
target in the tree.

| What | Where | Why it matters |
|---|---|---|
| `decodeEnvelope` | `envelope.go:430-457` | Parses the 16-byte WCF2 header from bytes that arrive over the network. Fuzzed (`FuzzDecodeEnvelope`). |
| `readFrameInto` | `h2.go:771-790` | Parses the HTTP/2 2-byte length prefix. Fuzzed (`FuzzReadFrame`, plus `FuzzReadFrameStream` added 2026-08-03). |
| `SessionDeduplicator.Accept` | `server_envelope.go:44-86` | 4096-wide replay window driven by an attacker-chosen sequence number. |
| `H3Server` request handling | `h3.go:33, 108, 112` | Server-side CONNECT-UDP entry; TLS state validation and MASQUE request parse. |
| `H2Server` request handling | `h2.go:35, 115` | Server-side stream entry. |
| Supplied-socket adoption | `supplied_socket.go` (entire file) | One day old at measurement time. Single-use enforcement, IP-literal requirement, peer matching, conflict detection. |
| Path migration | `h3_migration.go:40-141` | RFC 9000 migration onto a caller-supplied socket. |
| Anonymous credential handling | `authentication.go:36-60, 106` | Blind-token carrier auth path. |
| `privacyBucket` padding | `server_envelope.go:171-178`, `envelope.go:388-398` | Padding decisions are the fingerprinting defence; a bug here is a **detectability** finding, the top-ranked asset. |

**Ask specifically:** whether the WCF2 magic can ever appear unwrapped on the
wire in any code path; whether the fixed padding bucket set is itself
distinguishing; whether `Accept`'s window can be desynchronised.

### 0.2 `internal/masque` - 631 non-test / 235 test lines

RFC 9298 CONNECT-UDP. **This is a vendored fork of `quic-go/masque-go` v0.4.0
under MIT** (see [07](07-LICENSING-AND-COPYRIGHT-FINDINGS.md)). It parses peer
bytes heavily.

| What | Where |
|---|---|
| `ParseProxyRequest` | `proxy_request.go:36-111` - parses the peer's CONNECT request, URI template match, capsule header. Fuzzed. |
| `Conn.ReadFrom` | `conn.go:85-118` - parses the peer's datagram context-ID varint. |
| Capsule-stream reader goroutine | `conn.go:73-77` |

The local changes to upstream are documented in `internal/masque/UPSTREAM.md`
and are concurrency and lifetime fixes: nil-timer channel receives, canceled
read contexts, generation-fenced timer callbacks, idempotent close, and
observing close errors upstream discarded. **These deadlock and
use-after-close repairs are worth independent review** because they were
written against upstream behaviour rather than upstream tests.

### 0.3 `internal/pqauth` - 688 non-test / 427 test lines

All ML-DSA signing and verification, seed loading, key-ID derivation, the
device registry, and domain-separated signing.

| What | Where |
|---|---|
| Signature decode | `decode_fuzz_test.go` covers `FuzzDecodeSignature`, `FuzzVerifierSetDocument`, `FuzzVerifyDomainMessage` |
| ML-DSA verify | `pqauth.go:169-190, 323-340, 359-376` |
| Domain-separated message construction | `pqauth.go:387-403`, allow-list `:435-445` |
| Key-ID derivation | `pqauth.go:297-304` |
| Constant-time key-ID compare | `pqauth.go:687` (`crypto/subtle`) |
| Seed load and destroy | `pqauth.go:194-199, 244-262` - material present at `pqauth.go:199` |

**Ask specifically:** whether the shared fixed ML-DSA `ctx`
(`"Winn-Protocol-v2"`, `pqauth.go:36`) across all seven signing domains creates
any cross-domain confusion, given that separation relies solely on the
`domain || 0x00` prefix.

### 0.4 `internal/protocol` - 395 non-test / 218 test lines

Wire schema, transcript construction, and validation for the rekey exchange.
Small, dense, and load-bearing. Three fuzz targets
(`FuzzValidatePeerPublicKey`, `FuzzValidateRequest`, `FuzzValidateResponse`).

Transcript construction at `protocol.go:293-317` (request) and `:326-358`
(response); request digest at `:270`; PSK key-ID derivation at `:273-289`.

### 0.5 `internal/carrierauth` - 773 non-test / 313 test lines

Parses HTTP header claims from an unauthenticated peer, before the claim is
verified. Four fuzz targets. Entry: `Verify` (`auth.go:207`),
`VerifyAnonymous` (`:269`), header extraction (`:503`), timestamp parsing
(`:692`), replay ledger (`replay.go`).

### 0.6 `internal/echconfig` - 442 non-test / 124 test lines

ECHConfig generation, parsing and validation; installs ECH into `tls.Config`
and enforces `ECHAccepted` fail-closed. Two fuzz targets. Parsers at
`ech.go:272-367`. Note that in production the bytes usually arrive inside a
signed manifest, so this is signature-gated rather than raw, but the parser is
reachable from a local file path too (`ech.go:97-107`).

### 0.7 `internal/wcf3` - 468 non-test / 328 test lines

A complete second frame format with a replay window and privacy cells. Three
fuzz targets. **Not used in any production wire path** (see
[02](02-ARCHITECTURE-AND-DATA-FLOW.md#54-inner-session-framing-over-a-carrier)).
Review it only if it is intended to ship. Flagging it as dead-on-the-wire is
itself useful to an auditor, who would otherwise assume it is live.

### 0.8 `internal/privacytoken` - 888 non-test / 326 test lines

Blind RSA (RSABSSA-SHA384-PSS-randomized) token issuance and verification, via
`cloudflare/circl`. One fuzz target (`FuzzDecodeTokenHeader`). Issuer key
generation at `token.go:116`. This is the unlinkability mechanism, so a flaw
is a **privacy** finding, not only an authentication one.

### 0.9 `internal/tlsconfig` - 464 non-test / 348 test lines

Small but decisive. Every strict-hybrid and TLS-hardening decision in the
project is here: single-curve `CurvePreferences`, TLS 1.3 pinning, ticket and
renegotiation disabling, pinned root pool, post-handshake `validateState`.
`ParseSuite` is the function that determines the post-quantum property of the
whole system.

**New and unwired at snapshot time: `ApplyCoverProfile`.** This function
appeared at 2026-08-03 11:20 local time and is an anti-active-probing measure:
a listener presents an ordinary-web-server TLS profile to anything that has not
proven it is a Winn client, and routes genuine clients to the strict profile
via `GetConfigForClient`, gated on a matching private server name **and** the
presence of the Encrypted Client Hello extension.

Two things an auditor must be told rather than left to discover:

1. **The cover profile deliberately permits TLS 1.2** (`MinVersion:
   tls.VersionTLS12`), sets no `CipherSuites` and no `CurvePreferences`, leaves
   `SessionTicketsDisabled` false, and sets `ClientAuth: tls.NoClientCert`.
   Every one of those is a deliberate anti-fingerprinting choice, documented in
   the function's own comment: a server that refuses TLS 1.2, offers an unusual
   cipher list, never issues a session ticket, or requests a client certificate
   from a stranger is distinguishable by a single probe. The design intent is
   that the cover path is **not** a Winn security boundary. Whether the split
   is airtight, and whether a peer can reach the strict config through the
   cover path or vice versa, is exactly the kind of thing worth auditing.
2. **`ApplyCoverProfile` has no callers anywhere in the tree.** Grep confirms
   zero non-test call sites. It is implemented but not wired, so it currently
   protects nothing.

---

## Tier 1: Signed input, key material, and persisted secrets

Authentication has been checked, or is being checked, at these boundaries. Bugs
here are trust-model failures rather than memory-safety failures, and they tend
to be higher severity.

### 1.1 `internal/gatewaymanifest` - 1,880 non-test / 997 test lines

The compelled-infrastructure defence. Signature verification plus rollback,
equivocation, gap, predecessor-digest and transparency-inclusion checks.

`LoadVerifiedNodeV2` at `deployment_v2.go:110-188` is the single most
security-dense function in the tree. `VerifyV2` at `manifest_v2.go:163-201`.
Trust-state validation at `deployment_v2.go:198-207`. One fuzz target
(`FuzzDecodeManifestV2`).

**This is where a state-level attacker with legal leverage over a hosting
provider would attack.** Recommend disproportionate review time.

### 1.2 `internal/state` - 4,052 non-test / 2,069 test lines

Controller-side durable state. Generates the AWG PSK
(`state.go:530-540`, `postgres.go:724-734`), encrypts state at rest with
AES-256-GCM (`state.go:933-938`), holds the request-reconciliation ledger, and
implements the Postgres backend. Material present at `state.go:97`.

Also contains `credential_vault.go` (AES-GCM credential vault) and
`redemption_postgres.go` (single-use privacy-token ledger, the double-spend
defence).

### 1.3 `internal/securefile` - 1,147 non-test / 1,755 test lines

Every private-file read and write goes through here. TOCTOU-resistant open at
`securefile.go:280-337`; atomic write at `:14-52`; private directory
enforcement at `:353-381`.

**Known defect to confirm:** `permissions_unix.go:7, 11, 13` are no-ops, so
file ownership is never verified on Unix. Windows has real checks
(`permissions_windows.go:14, 44, 69`).

### 1.4 `internal/bootstrap` - 821 non-test / 677 test lines

Both sides of the control-plane HTTP exchange, and the ordering of every
server-side check. Small for its importance. `server.go:66-321` is the entire
server request path; `client.go:60-214` the client path. The log-blinding HMAC
is at `server.go:387-401`.

### 1.5 `internal/rotation` - 812 non-test / 625 test lines

Crash-safe rekey state machine: persist-before-transmit, fail-closed revoke on
apply error, generation tracking. `coordinator.go:194-256`. Note that `Rotate`
is called from only two non-test sites and **not** from the connect path (see
[02](02-ARCHITECTURE-AND-DATA-FLOW.md#41-a-structural-finding-first)).

### 1.6 `internal/pki` - 329 non-test / 0 test lines

Generates every private key in the system: CA, server and device ECDSA P-384,
the 32-byte state key, the 32-byte audit key, four ML-DSA seeds, ECH X25519
keys, and the privacy-token RSA-3072 key. All written `0600`.

**Zero test lines.** For a package that generates all key material, that is
itself worth noting.

### 1.7 `internal/identity` - 53 non-test / 211 test lines

SPIFFE URI SAN extraction from the verified certificate chain
(`identity.go:14-53`). Tiny, but it is the sole source of authenticated device
identity on the server, and it is what prevents cross-device impersonation.
Good test ratio.

### 1.8 `internal/audit` + `internal/auditcheckpoint` - 298 + 1,512 non-test lines

HMAC-chained tamper-evident logging and the checkpoint/custody mechanism. The
server refuses to serve when the audit sink is unhealthy
(`bootstrap/server.go:69-76`), so a bug here is an availability issue as well
as an integrity one.

### 1.9 `internal/transparency` - 350 non-test / 167 test lines

Inclusion-proof verification used by the manifest path. Small; review with 1.1.

### 1.10 `internal/awg` - 274 non-test / 155 test lines

Applies the PSK to the AWG peer, and reads it back by parsing `awg show`
output (`applier.go:165-261`). Sits on both a key-material boundary and a
subprocess boundary. Material present at `applier.go:128`.

### 1.11 `internal/ratelimit` - 91 non-test / 54 test lines

Per-device, per-IP rate limiting on the control plane. Small and worth a quick
look for bypass by IP spoofing or device-ID variation.

### 1.12 `internal/revocation` - 733 non-test / 317 test lines

**This package did not exist when this audit package was started. It appeared
at 2026-08-03 11:15 local time, roughly ten minutes before the final
measurement snapshot.** It is listed here because revocation logic is
security-relevant by definition, but it has had no review of any kind, is not
described anywhere else in this package, and its integration points are
**UNVERIFIED**. Treat it as new code. See
[04](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md#12-code-that-landed-during-preparation-of-this-package).

---

## Tier 2: Subprocess and operating-system boundary

Winn shells out to five external binaries and parses their output, and it
manipulates privileged system state. This is a genuine trust boundary and it is
where an auditor is most likely to find something exploitable that is not a
cryptographic finding.

### 2.1 `internal/directawg` - 5,566 non-test / 4,525 test lines

The largest `internal/` package and the only one referencing AmneziaWG. Brings
up the Linux session, installs routes, installs the fail-closed nftables kill
switch, manages DNS policy, and supervises the `amneziawg-go` child.

| Concern | Where |
|---|---|
| Session bring-up, ordered | `linux_controller_common.go:255-594` |
| Exec boundary, generic | `linux_exec.go:19, 33, 62` |
| Exec allow-list | `exec_allowlist.go:64`, with its own honest limitations documented at `:22-63` |
| AWG status parsing | `status_cli.go:63, 130, 192, 212, 233, 246` |
| Route transaction and rollback | `linux_route.go` |
| nftables and DNS policy | `linux_policy.go:58-100, 401-409, 456-457, 510-519` |
| nft health check | `linux_policy.go:628-645` - **`strings.Contains` substring match** |
| Ordered teardown | `linux_session.go:197` |
| Socket marking with read-back verification | `linux_socket_linux.go:24-38, 116-140` |
| Signed deployment profile verification | `linux_profile.go:132-145` |
| Secret file write and prompt deletion | `linux_controller_common.go:340-379, 435-440` |

**Ask specifically:** whether the kill switch can be defeated by a failure
ordering; whether `linux_policy.go:628` can be fooled by a crafted set element;
whether the exec allow-list gaps documented at `exec_allowlist.go:37-42` are
reachable.

### 2.2 `internal/preparation` - 5,435 non-test / 5,112 test lines

Pre-connect assembly: carrier, credentials, PSK pool, policy anchor. Contains
its own subprocess runner with a genuine 2-entry path allow-list
(`linux_underlay_runner_linux.go:55, 66, 32-47`), which is the stricter of the
two exec patterns in the tree.

### 2.3 `internal/linuxauto` - 1,845 non-test / 1,862 test lines

The Linux auto-connect runtime and deployment loader. Attempt-identity
reservation before any network work (`runtime.go:110-178`); trust-state commit
ordering (`deployment_loader.go:114`).

### 2.4 `internal/connectivity` - 2,212 non-test / 1,673 test lines

Candidate racing, verification predicates, mode policy, single-flight gating,
deadline and cleanup reserve. `coordinator.go:153-232, 276-321, 605-802,
945-981`. The predicate ordering at `:945-981` is a leak-prevention control:
a candidate must prove a fresh handshake and bidirectional reachability before
DNS or canary checks.

### 2.5 `internal/h3candidate` - 3,415 non-test / 3,057 test lines

Adapts the H3 carrier to the candidate contract. Contains the second,
independent ECH enforcement gate (`candidate.go:519-543`) and the protected
underlay lease. Worth reviewing alongside `internal/carrier`.

---

## Tier 3: Host-application boundary

The caller is trusted to be the host app; the bytes it sends are not. These are
the surfaces mobile and desktop integrations will exercise.

| Directory | Non-test / test | Entry points |
|---|---|---|
| `datapath` | 1,581 / 1,236 | `config.go:220` (config JSON), `engine.go:384-471` (raw gateway UDP with off-path sender filter), `socket.go:33, 78` (fd adoption), `carrier.go:76-90, 118-232` |
| `datapath/duplex` | 550 / 664 | `duplex.go:275, 289` - framed host-to-subprocess protocol; every parse error is terminal and latched |
| `cdatapath` | 268 / 0 | `winn_datapath.go:123, 151, 175` - the C ABI for iOS and macOS. **Zero test lines, and excluded from `go build ./...` whenever `CGO_ENABLED=0`, which is what the release script and every scanner run use.** |
| `cshared` | 161 / 0 | `c-shared` build for desktop FFI. **Zero test lines, same CGO exclusion.** |
| `clientbinding` | 223 / 144 | The cross-platform facade. `TunnelSupported()` returns false everywhere (`binding.go:62`). |
| `internal/sysconv` | 93 / 124 | Integer conversion helpers used at the FFI boundary; small but relevant to overflow questions. |

**`cdatapath` and `cshared` deserve attention out of proportion to their size**:
they are the only `import "C"` packages, they carry the FFI memory-safety
surface, they have no tests, and no automated gate in this repository compiles
them.

---

## Tier 4: Orchestration and policy with security consequences

Not directly parsing adversary bytes, but a bug produces a security-relevant
outcome.

| Directory | Non-test / test | Why it matters |
|---|---|---|
| `internal/realcycle` | 4,548 / 3,318 | Admission and cycle control. One fuzz target on JSON duplicate-name handling. |
| `internal/mobility` | 412 / 216 | Carrier selection scoring and failure cooldown (`engine.go:243, 356, 368`). Selection bias is a fingerprinting concern. |
| `internal/measurement` | 1,297 / 620 | HMAC-signed measurement records. |
| `internal/producersnapshot` | 1,275 / 560 | Snapshot integrity. |
| `internal/realtopology` | 1,145 / 669 | Topology manifest handling; one fuzz target on JSON nesting depth. |
| `internal/phase1anchor` | 1,237 / 1,803 | Anchor trust for build and deployment pinning. |
| `internal/netdial` | 389 / 106 | Happy Eyeballs plus NAT64 synthesis. Consumes resolver answers an attacker can influence (`happy.go:201, 243`), and a mis-race can leak outside the tunnel. |
| `internal/observability` | 148 / 52 | Check that nothing sensitive is emitted. |
| `internal/closedarchive` | 646 / 612 | Evidence sealing. |
| `internal/costledger`, `internal/anchorfixture`, `internal/connectivity` helpers | small | Low priority. |

---

## Tier 5: Deprioritise

**49 directories, 55,579 non-test lines, half the tree.** These are
harnesses, evidence tooling, fixture generators, and operational commands. They
do not run on user devices and do not process adversary input in production.
An auditor should confirm that characterisation quickly and then stop.

The largest are:

| Directory | Non-test lines | What it is |
|---|---|---|
| `cmd/winn-phase1-soak-controller` | 17,081 | Soak-test controller. Largest single directory in the tree by a wide margin. 20 of its files compile only under `-tags winn_incomplete_e8`, which **no script in the repository passes**, so they are never vetted or race-tested. |
| `cmd/winn-phase1-matrix-verify` | 5,059 | Verification matrix harness. |
| `cmd/winn-phase1-controller-close` | 3,685 | Controller close protocol harness. |
| `cmd/winn-phase1-conservation-smoke` | 2,200 | Smoke harness. |
| `spikes/ios_maximum_privacy/*` | 7,831 total | iOS privacy spike, 5 Go packages plus 40 Swift files and a native engine. **In the same Go module**, so `go test ./...` runs it, including a test that requires root. |
| `cmd/winn-auto-e2e` | 1,738 | The only end-to-end connect harness. Read it as documentation of the intended flow, not as shipping code. |
| `cmd/winn-leak-v2` + subpackages | 3,605 total | Leak-detection acceptance suite. |
| Remaining 30 `cmd/` packages | ~6,500 | Operational CLIs: `winn-pki`, `winn-token`, `winn-admin`, `winn-audit`, `winn-cost`, `winn-manifest`, and similar. |

Two `cmd/` packages are exceptions and should be read in tier 1 alongside
`internal/bootstrap`: `cmd/winn-server` (336 lines, the controller entry point,
including loopback enforcement for the admin listener at `main.go:305-315`) and
`cmd/winn-carrier-server` (576 lines, which takes its entire configuration from
the **verified** manifest outside lab mode, `main.go:178-254`). Note
`cmd/winn-carrier-server` has **zero test lines**.

---

## Cross-cutting: every `os/exec` call site in non-test code

Included because it is the question an auditor asks first and it is tedious to
reconstruct.

**Library and production packages:**

| Site | Command source | Fixed allow-list? |
|---|---|---|
| `internal/directawg/linux_exec.go:33` (`Run`) | `command.Path` from config | **No.** Only absolute/regular/executable validation via `os.Stat`, which follows symlinks (`linux_controller_common.go:1221`) |
| `internal/directawg/linux_exec.go:62` (`Start`) | Same | **No.** Same validation |
| `internal/directawg/status_cli.go:139` | `source.binary` from config | **No** for the path. Arguments are constrained: literal `"show"`, regex-validated interface name, field from a 3-item allow-list (`:108-112`) |
| `internal/preparation/linux_underlay_runner_linux.go:77` | `command.Path` | **Yes.** 2-entry map, enforced at `:66`, non-symlink regular executables required at `:32-47` |
| `internal/awg/applier.go:143` (`Apply`) | `-awg-bin` flag | **No.** Absolute/regular/executable plus an interface-name regex (`:221-243`, `:102`) |
| `internal/awg/applier.go:183` (`ReadCurrentPSK`) | Same | **No.** Same validation |
| `internal/anchorfixture/anchorfixture.go:115, 266, 331` | `exec.LookPath("go")` | **No.** Fixture-support package |

**Harnesses with an allow-list enforced:** `cmd/winn-auto-e2e/main_linux.go`
(built `:554`, enforced `:1607, :1643`), `cmd/winn-acceptance/main.go`
(`:210`, `:655, :684`), `cmd/winn-aicore-directawg-e2e/main.go` (`:398`),
`cmd/winn-h3-e2e/main_linux.go` (`:473`), `cmd/winn-teardown-e2e/main_linux.go`
(`:289`), `cmd/winn-leak-v2/client_linux.go` (`:212`).

**Harnesses with no allow-list:**
`cmd/winn-real-cycle-admitted-launcher/runtime_linux.go:186`,
`cmd/winn-phase1-soak-controller/admitted_runner_linux.go:24`,
`cmd/winn-phase1-soak-controller/e8_rehearsal_linux.go:215`,
`cmd/winn-phase1-soak-controller/execrunner_unix.go:77`,
`cmd/winn-phase1-soak-success-fixture/main.go:49`,
`cmd/winn-phase1-anchor-pin/main.go:455`,
`cmd/winn-phase1-controller-close/main.go:186, 869, 908`,
`spikes/ios_maximum_privacy/matrixverify/main.go:883`.

**Asserted `os/exec`-free by their own tests:** `cmd/winn-datapath`
(`main.go:11-12`), `datapath` (`doc.go:7`),
`cmd/winn-phase1-soak-controller/systemdunit.go` (`:6`).

### The allow-list's honest limits

`LinuxExecAllowList` (`internal/directawg/exec_allowlist.go:64`) documents its
own scope at `:22-63`, and the documentation is accurate:

- It pins **path-name strings** by exact equality. No inode pinning, no content
  digest, no symlink resolution, no path normalisation (`:28-35`, `:111`).
- It is **per-runner, not per-process** (`:36-37`).
- **Two exec boundaries in its own package are not covered by it**:
  `execLinuxRunner` (`linux_exec.go`, which the default controller and policy
  paths use) and `runBoundedStatusCommand` (`status_cli.go`) (`:37-42`).
- A nil receiver is a refusal, not a pass (`:103-110`).

An attacker who can write to `/opt/winn-lab/bin/` or replace a symlink target
defeats it. Whether that is reachable in the deployment model is a question for
the engagement.

---

## Cross-cutting: fuzz coverage against the exposure ranking

24 fuzz targets exist. 9 run in the release gate. Mapping coverage onto the
tiers above:

| Tier 0/1 component | Fuzzed? | In the gate? |
|---|---|---|
| `internal/carrier` envelope and framing | Yes, 3 targets | 2 of 3 |
| `internal/masque` proxy request | Yes | **No** |
| `internal/pqauth` decode paths | Yes, 4 targets | 1 of 4 |
| `internal/protocol` validation | Yes, 3 targets | 3 of 3 |
| `internal/carrierauth` claims | Yes, 4 targets | 1 of 4 |
| `internal/echconfig` config parsing | Yes, 2 targets | **0 of 2** |
| `internal/gatewaymanifest` decode | Yes, 1 target | **No** |
| `internal/privacytoken` header decode | Yes | Yes |
| `internal/wcf3` (not on the wire) | Yes, 3 targets | 1 of 3 |
| `internal/state` state decode | **No** | No |
| `internal/securefile` | **No** | No |
| `internal/directawg` status parsing | **No** | No |
| `internal/awg` PSK readback parsing | **No** | No |
| `datapath/duplex` frame decode | **No** | No |
| `datapath` config parse | **No** | No |

The unfuzzed rows in the lower half are the recommendation an auditor will
make anyway. They are listed here so the recommendation costs nothing to
produce.
