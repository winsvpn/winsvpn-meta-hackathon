# Winn Protocol v3 — Server-Side Readiness Review

**Status: NON-AUTHORITATIVE.** Independent review feeding an external audit.

| | |
|---|---|
| Reviewer | Claude Opus 5, acting as the server-side lane |
| Date (local) | 2026-08-03 |
| Scope root | `/Users/owner/Documents/wins/source/wins_vpn/winn_protocol_experimental/` |
| Module | `winsvpn.local/winnprotocol`, Go 1.26.0 (toolchain go1.26.5) |
| Baselines at time of writing | `go build ./...` clean · `go vet` clean on all server packages · server-side package tests pass |
| Concurrent editors | Four other lanes were editing this tree during the review (handshake, carrier-socket, fuzzing, Fugu). All findings were taken from the tree as read on 2026-08-03. |

**Headline.** The gateway's cryptographic core, audit design, state machine, and
operator runbook are of unusually high quality. The gateway is **not production
ready**, and the reason is not cryptography. It is that the endpoint announces
what it is to anyone who connects, that its rate limiter cannot see
unauthenticated traffic, that device revocation never reaches the data plane,
and that the database keeps in plaintext the identifier every other subsystem
carefully hashes.

---

## 0. What I exercised versus what I read

This distinction is load-bearing. Read the tables before the findings.

### Exercised — I ran this and observed the output

I built and started a real `winn-carrier-server` (lab mode, generated lab PKI
via `cmd/winn-pki`) on `127.0.0.1:19445` with a UDP echo backend, and drove it
with OpenSSL 3.6.3 and a purpose-built Go probe harness that imports nothing
from the module under test.

| # | Test | Result |
|---|---|---|
| T1 | TLS probe: default browser-like ClientHello | Full handshake, **server certificate delivered**, then `certificate required` (alert 116) |
| T2 | TLS probe: TLS 1.2 only | Refused, `New, (NONE), Cipher is (NONE)` |
| T3 | TLS probe: TLS 1.3, groups `X25519:P-256:P-384` | **`handshake failure` (alert 40)** after 7 bytes read, 219 written. No HelloRetryRequest |
| T4 | TLS probe: correct hybrid group, ALPN `http/1.1` | Handshake proceeds, ALPN `http/1.1` negotiated on the H2 listener |
| T5 | TLS probe: correct group, no client certificate | Handshake proceeds to certificate delivery, then alert 116 |
| T6 | `certificate_authorities` leak | **`CN=Winn Protocol Experimental Lab CA` handed to an unauthenticated prober** |
| T7 | Plaintext HTTP to the TLS port | `HTTP/1.0 400 Bad Request` + `Client sent an HTTP request to an HTTPS server.` (Go stdlib string) |
| T8 | 512 random bytes to the TLS port | No application response |
| T9 | Truncated ClientHello, then silence | **Connection held 8.001 s**, then EOF |
| T10 | HTTP-layer probes over valid ECH + valid mTLS (9 cases: wrong path, wrong method, no media type, no auth headers, garbage signature, query string, path traversal) | 404 / 405 / 415 / 401, all `text/plain`, generic status text, latencies 97 µs – 3.7 ms |
| T11 | 3000 concurrent pre-handshake connections from one unauthenticated source | **All 3000 parked, 0 dial failures, in 613 ms** (132 ms on a warm run) |
| T12 | `/readyz` during the flood | `200 "ready"` — liveness unaffected |
| T13 | Operational log under flood | **Exactly 3000 lines, each containing the raw client `IP:port`** |
| T14 | `/metrics` content | Aggregate event counters only. No per-user, per-device, or per-IP labels |
| T15 | Metrics listener binding | Loopback enforced at startup (`requireLoopbackAddress`) |
| T16 | Audit log content after a full session | Start/stop records only; `device_hash` is HMAC'd; no IP anywhere |
| T17 | SIGTERM | Clean exit < 2 s, `readyz` 200 → process gone, `carrier_server_stopped` sealed into the audit chain |
| T18 | Post-fix re-run of T11/T13 | 3000 lines, **0 peer IPs**, 3000 × `[redacted-peer]`, error class preserved, no functional regression |

### Read — source analysis only, not executed

- `winn-server` and `winn-token-issuer` were built but **not started**. Their
  probe and rate-limit behaviour is inferred from source, structurally identical
  to the carrier's.
- Replay across processes/nodes (G6): I could not capture and replay a live
  TLS+HTTP/2 authenticated request. The finding is from reading
  `internal/carrierauth/replay.go`.
- Manifest expiry at runtime (G5): read-only. Non-lab manifest mode was not
  exercised.
- PostgreSQL schema and contents (G3): read from `schema/postgres_v1.sql` and
  `internal/state/postgres.go`. **No database was stood up.**
- Anonymous-token mode was **not exercised** — it requires a signed manifest and
  a durable Postgres redemption store. All anonymous-mode findings are from
  reading.
- Nothing was tested on Linux. The host was macOS (darwin 25.6.0). The
  `securefile` Unix/Windows asymmetry (G8) was read, not exercised.

---

## 1. What actually constitutes the server side

The brief was right to insist this be established first. `winn-carrier-server`
is **not** the whole story. Of 38 commands in `cmd/`, exactly **three** are
internet-facing long-lived server processes, and they are meant to run on
**separate hosts under separate service accounts**:

| Binary | Role | Listens | Client auth |
|---|---|---|---|
| `cmd/winn-server` | **Control plane.** Issues/rotates AWG pre-shared keys. The security-critical one — it holds controller state, the state key, and the AWG applier | `0.0.0.0:9443` (HTTP/1.1 over mTLS) + loopback admin `:9095` | mTLS + ML-DSA, always |
| `cmd/winn-carrier-server` | **Data plane.** MASQUE/H3 + H2 carrier relaying inner AWG UDP to a fixed backend | `0.0.0.0:443` TCP **and** UDP + loopback metrics `:9092` | mTLS + ML-DSA, **or** anonymous blind token |
| `cmd/winn-token-issuer` | **Privacy-token issuer.** Blind-RSA signer for anonymous carrier authorization | `:9444` | mTLS + ML-DSA, always |

Deliberate and correct: the issuer must never hold carrier keys, and the carrier
must never hold the issuer's RSA private key (`deploy/systemd/README.md`).

Supporting operator tools, not servers: `winn-pki` (explicitly "a disposable
interoperability generator", not a production CA), `winn-admin` (revoke /
snapshot / abort-pending), `winn-manifest` (v1 manifests only), `winn-audit`,
`winn-cost`. `cmd/winn-phase1-anchor-server` is a test-harness anchor, not part
of the production surface. `cmd/winn-client`, `winn-carrier-client`,
`winn-datapath`, `winn-acceptance` are client/test side.

Server-relevant internal packages: `bootstrap` (the controller HTTP handler —
this is where `winn-server`'s logic lives, 570 lines), `carrier`, `carrierauth`,
`privacytoken`, `ratelimit`, `identity`, `pqauth`, `pki`, `gatewaymanifest`,
`transparency`, `observability`, `audit`, `state`, `securefile`, `tlsconfig`,
`echconfig`.

On the framing in the brief: confirmed. AmneziaWG appears in `internal/awg`
(429 lines) and `internal/directawg`; it is one backend/carrier choice. The
protocol core is hybrid ML-KEM + X25519/P-256/P-384 TLS 1.3 with ML-DSA-65/87
request and response signatures.

---

## 2. Gap list, ranked by what blocks production

### P0-1 — Probe resistance is effectively absent. This is the blocker.

**Tested (T1–T8).** Five independent discriminators, **any one of which**
confirms the endpoint is not an ordinary web server, on a single connection,
with no authentication:

1. **Only one named group is offered.** `internal/tlsconfig/tlsconfig.go:85`
   sets `CurvePreferences: []tls.CurveID{suite.Curve}`. A perfectly ordinary
   ClientHello offering X25519/P-256/P-384 is answered with **`handshake_failure`
   after 7 bytes** — not a HelloRetryRequest, not a negotiation. No real website
   behaves this way. Measured in T3.
2. **TLS 1.2 is refused.** `MinVersion == MaxVersion == VersionTLS13`
   (`tlsconfig.go:83-84`). Measured in T2.
3. **ECH is mandatory.** `echconfig.ConfigureServer(cfg, keys, true)` installs a
   `VerifyConnection` hook that rejects `!state.ECHAccepted`
   (`internal/echconfig/ech.go:229-231`). A non-ECH client completes the entire
   handshake, **receives the real server certificate**, and is then killed with
   `bad_certificate`. Real ECH deployments serve the public-name site to non-ECH
   clients; refusing them is unique behaviour. Measured in T1/T5.
4. **`certificate_authorities` is leaked.** In identity mode
   (`ClientAuth: RequireAndVerifyClientCert`) Go's TLS 1.3 server populates the
   CertificateRequest's `certificate_authorities` from `ClientCAs`. T6 measured
   an unauthenticated prober receiving `CN=Winn Protocol Experimental Lab CA`.
   **In production this is the real Winn CA's Distinguished Name — single-probe,
   zero-ambiguity attribution of the endpoint and, by extension, of every user
   behind it.** This one is the worst of the five and the cheapest to exploit.
5. **Go's stdlib fingerprint.** Plaintext to the TLS port returns
   `Client sent an HTTP request to an HTTPS server.` (T7).

There is **no decoy origin, no cover traffic, and no fallback proxy anywhere in
the tree** — I grepped for `decoy`, `camouflage`, `probe.resist`, `cover traffic`
and found only unrelated test fixtures.

Note the genuine strengths this sits alongside: mandatory ECH means the prober
never learns the inner SNI; the HTTP layer (T10) is generic Go `http.Error` text
with no Winn-specific strings and no measurable timing oracle at ~100 µs
granularity; anonymous-token mode (`ServerAnonymousForALPN`) removes client
certificates entirely and is the right architecture. The problem is that the
adversary never has to reach the HTTP layer.

**Recommended (not landed — this is a design decision, not a patch):**
switch anonymous-token mode to the default for internet-facing carriers so
finding 4 disappears; add classical groups to `CurvePreferences` alongside the
hybrid and enforce the hybrid requirement in `VerifyConnection` instead, so
finding 1 becomes a post-handshake rejection rather than a pre-handshake
signature; and give the listener a real cover origin so that non-ECH, wrong-group,
and wrong-path traffic is proxied to a plausible site instead of being refused.
Until then, treat any deployed IP as burned once probed.

### P0-2 — Device revocation never reaches the data plane

**Read.** `winn-admin -action revoke` writes to the controller's
`winn_revoked_devices` table; `internal/bootstrap/server.go:344-346` turns
`state.ErrRevoked` into HTTP 403. But **`cmd/winn-carrier-server` never consults
revocation at all** — I grepped: its only `state.*` usage is
`state.OpenPostgresRedemptions` for privacy tokens (lines 328–343), and
`carrierauth.RequestVerifier.Verify` authorizes purely from the static
`device-pq-registry.json` file.

So a revoked device is cut off from rekeying but **keeps full carrier data-plane
access** until an operator hand-edits the registry JSON on every carrier node and
restarts them. Neither `OPERATIONS.md` §8 nor `SECURITY.md` states this
limitation. Compounding it, there is **no CRL and no OCSP anywhere** (the lab CA
sets `KeyUsageCRLSign` and never uses it), leaf certificates are 1 year and the
CA is 10 years.

For a system whose users face physical risk, "we revoked the compromised device"
currently means "we revoked it from key rotation only."

### P0-3 — PostgreSQL stores the one identifier everything else hashes

**Read.** `internal/audit/audit.go:276-281` HMACs device IDs into `device_hash`,
and `internal/bootstrap/server.go:383-418` goes to remarkable lengths to keep
device IDs out of stdout, HMAC'ing even the request ID under a per-process random
key. Then `schema/postgres_v1.sql` stores `device_id text` **verbatim** in three
tables:

- `winn_peers (controller_id, device_id, peer_public_key, ..., issued_at, expires_at)`
- `winn_requests (controller_id, request_id, device_id, peer_public_key, digest, response_envelope, created_at, committed)`
- `winn_revoked_devices (controller_id, device_id, revoked, updated_at)`

`winn_requests` is purged opportunistically after 24 h, and only when rekeys are
happening. **`winn_peers` and `winn_revoked_devices` have no retention policy at
all** — device IDs, AWG peer public keys, and per-device issuance timestamps
persist indefinitely. `SECURITY.md:53-55` already warns that a backup plus the
state key decrypts retained response envelopes.

Good news within this: no IP addresses are persisted anywhere in the schema, and
`winn_privacy_token_redemptions` is genuinely unlinkable by construction.

The fix is not hard — hash `device_id` on the way into Postgres the way the audit
log already does — but it is a schema migration and a correctness question for
the rotation state machine, so it is out of scope for a review-lane patch.

### P1-4 — Operational log leaked every peer IP · **FIXED, landed, verified**

**Tested (T13), fixed, re-tested (T18).** `net/http` interpolates the peer
address into TLS handshake diagnostics and the format string is not
configurable:

```
http: TLS handshake error from 203.0.113.7:44100: unexpected EOF
```

All three servers routed this to stderr — `winn-server` explicitly
(`ErrorLog: log.New(os.Stderr, "tls: ", 0)`), the carrier and issuer implicitly
via Go's default logger — and systemd sends it to journald. T13 measured **3000
log lines carrying 3000 raw client addresses, produced by an unauthenticated
attacker in 613 ms.**

Two harms in one. A durable record of which addresses reached a circumvention
endpoint is exactly the enumeration artifact the threat model forbids, and it
directly contradicts `SECURITY.md:31`. It is also an unauthenticated log
amplification and disk-fill channel.

Fixed — see §3.

### P1-5 — The rate limiter cannot see unauthenticated traffic

**Tested at the connection layer (T9, T11); ordering read from source.**

`ratelimit.BucketLimiter` itself is sound: token bucket, bounded key count,
idle pruning, and it **fails closed** (`ratelimit.go:59-63` denies when the map
is full). But it is keyed on `principal|IP` and therefore cannot run until the
principal is known. In both `internal/carrier/h2.go:144` and
`internal/carrier/h3.go:154` the call sits **after**
`authenticateCarrierRequest`, i.e. after ML-DSA verification and, in anonymous
mode, after RSA blind-token verification. `internal/bootstrap/server.go:117` has
the same ordering.

Consequences:

- **Pre-authentication, the only control is a global concurrency semaphore**
  (`-max-concurrent`, default 1024 carrier / 128 controller) applied inside the
  HTTP handler — i.e. after TLS. Nothing limits connections.
- T11 measured **3000 concurrent pre-handshake connections parked from a single
  source, zero dial failures**, each held **8.001 s** (T9, matching
  `ReadHeaderTimeout`). There is no `netutil.LimitListener`, no per-IP
  connection cap, and no accept-rate limit on any of the three listeners.
- In anonymous-token mode there is no client certificate, so an unauthenticated
  peer reaches signature verification on every request.

Liveness held up well under T11/T12 (`/readyz` stayed 200), so this is a
resource-exhaustion and cost concern rather than an immediate crash risk — but
the attacker's cost is near zero and unbounded.

One deliberate, correct decision worth crediting: in anonymous mode the durable
token redemption happens **after** proof-of-possession of the token's committed
ML-DSA key (`internal/carrier/authentication.go:113-119`), which prevents
unauthenticated token burning. That ordering is right and should not be changed
to fix the above.

Secondary: because the limiter key includes the source IP, one authenticated
principal spread across many IPs inflates the map toward `-rate-max-keys`
(default 100k); once full, **new legitimate identities are denied**. Failing
closed is the right call, but it is a lockout lever.

### P1-6 — Gateway manifest expiry is checked only at startup

**Read.** `gatewaymanifest.LoadVerifiedNode` / `LoadVerifiedNodeV2` are called
once in `cmd/winn-carrier-server/main.go:178` and `:213`, with
`time.Now().UTC()` evaluated at that moment. There is no ticker, reload, or
re-verification; after startup the manifest is flattened into local variables and
never re-examined. A long-running carrier **serves indefinitely on an expired
manifest** (max lifetime 7 days) until someone restarts it. Only operational
alerting covers this.

The v2 trust state is otherwise excellent — sequence-rollback, equivocation, and
predecessor-digest checks, with `BootstrapTrustStateV2` deliberately separated so
deleting local trust state cannot silently trigger trust-on-first-use. v1 has
**no sequence pin at all** and accepts any older, still-unexpired,
still-inclusion-proven manifest; v1 should be considered deprecated.

### P1-7 — Identity-mode replay protection is per-process and in-memory

**Read.** `carrierauth.ReplayCache` is a `map[string]time.Time` in one process.
Within the ±2 minute skew window, a captured authenticated carrier request can be
replayed **to a different carrier node, or to the same node after a restart**.
Anonymous-token mode is not affected — its redemption store is durable in
Postgres and single-use. So the weaker guarantee applies to the *stronger-looking*
authentication mode.

### P2-8 — `securefile` has no ownership check on Unix

**Read.** `internal/securefile/permissions_unix.go` is 13 lines and all three
hooks are no-ops. Private-secret validation on Unix is mode-only
(`perm&0o077 == 0`) plus good symlink/regular-file/`SameFile` TOCTOU defenses. A
`0600` controller seed, state key, audit key, or credential-vault key owned by a
**different UID** is accepted. `permissions_windows.go` (191 lines) enforces owner
SID equality, `SE_DACL_PROTECTED`, and an exact three-ACE DACL. `SECURITY.md:34-36`
describes the intent accurately, so the asymmetry looks deliberate — but on the
platform that actually ships, it is the weaker half.

### P2-9 — Deployment is reproducible but bare

**Read** (no deployment was performed).

- **No container image, no Dockerfile, no CI, no IaC, no Makefile.** Docker
  appears only as a disposable Postgres test fixture.
- What does exist is good: four hardened systemd units in `deploy/systemd/`
  (`ProtectSystem=strict`, `ProtectProc=invisible`, `MemoryDenyWriteExecute`,
  `NoNewPrivileges`, `UMask=0077`, capability split, secrets via
  `LoadCredential=`, separate service accounts), a cross-compiling
  `scripts/build_release.sh` with CycloneDX SBOM, offline SLH-DSA release
  signing, and a byte-for-byte reproducibility check.
- **Configuration is flags-only** — 28/36/15 flags across the three servers,
  with systemd `EnvironmentFile` variables interpolated into `ExecStart`. There
  is no config-file schema and no config validation beyond per-flag checks.
  `config/` holds client-side network-impairment test matrices, not server config.
- Postgres schema is hand-applied via `psql`, version-pinned to 1, and the
  service **fails closed** if the installed version differs. DSN must be
  `sslmode=verify-full`. Auto-migrate is gated behind `-lab-mode`. All good.
- `OPERATIONS.md` is a genuine 13-section runbook and `PRODUCTION_READINESS.md`
  honestly enumerates 16 deployment-owner gates.

### P2-10 — Housekeeping

- Large build artifacts are committed at the repo root (`winn-auto-e2e` ~10 MB,
  `winn-phase1-soak-controller` ~8.5 MB, `matrixverify`, `evidenceverify`,
  `winn-phase1-matrix-verify.exe`).
- `.gitignore` does **not** exclude `*.pem`, `*.key`, or `*.seed`. Nothing
  structurally prevents a future lab-PKI run inside the tree from landing key
  material. Recommend adding those patterns.
- `evidence/leak-v2-acceptance-20260724/provider-known-hosts` contains SSH host
  **public** keys for acceptance VPS machines — not secret, but an
  infrastructure fingerprint.
- A repo-wide search for committed private key material found **none**. Test
  fixtures are generated at runtime into `t.TempDir()`.

---

## 3. Fixes landed

One fix, chosen because it was the only one that was simultaneously
safety-critical, cheap, and free of design risk. Everything else above is
reported, not patched.

### Peer-address redaction in operational logs (P1-4)

**New files**

- `internal/observability/errorlog.go` — `PeerRedactingWriter`, `ErrorLogger`,
  and `RedactAddresses`. Every whitespace-delimited token that parses as
  `netip.Addr` or `netip.AddrPort` — after stripping trailing log punctuation,
  including bracketed IPv6 — is replaced with `[redacted-peer]`. Non-address
  tokens (error classes, event names, suite names) are preserved, so the line
  keeps its operational meaning. `Write` returns the caller's byte count so
  `log.Logger` does not report a spurious short write.
- `internal/observability/errorlog_test.go` — six redaction cases (IPv4+port,
  the ECH-rejection line, bracketed IPv6, bare IPv6, bare IPv4, a
  no-address control) plus logger-integration, byte-count, and nil-sink tests.

**Modified files** (four lines of real change each, all outside `internal/carrier`)

- `cmd/winn-server/main.go` — `httpServer.ErrorLog` and `adminServer.ErrorLog`
  now use `observability.ErrorLogger`.
- `cmd/winn-carrier-server/main.go` — `h2Service.ErrorLog` and
  `metricsService.ErrorLog` added.
- `cmd/winn-token-issuer/main.go` — `server.ErrorLog` added; `observability`
  added to imports.

**Verification (T18).** Rebuilt the carrier, re-ran the 3000-connection flood:
3003 log lines, **zero peer IP:port**, 3000 × `[redacted-peer]`, 3000 ×
`unexpected EOF` preserved. HTTP probe suite re-run afterwards — identical
results, no functional regression. `go build ./...`, `go vet`, and the
server-side package tests all pass.

**Scope limit, stated plainly.** This closes the `net/http` channel. The HTTP/3
listener is `quic-go`'s `http3.Server`, whose logging goes through a separate
`*slog.Logger` that these servers leave unset (so it is silent today) — but that
is a different code path and I did not exercise it. Anyone enabling quic-go
logging must apply the same redaction.

**Files touched — complete list**

```
internal/observability/errorlog.go        (new)
internal/observability/errorlog_test.go   (new)
cmd/winn-server/main.go                   (modified)
cmd/winn-carrier-server/main.go           (modified)
cmd/winn-token-issuer/main.go             (modified)
docs/reviews/server-readiness-20260803/   (new, this review)
```

Nothing under `internal/carrier`, `docs/handoff/`, `evidence/`, or any
append-only log was modified. No key material appears in any file or log
produced by this review.

---

## 4. What is genuinely good

Recording this so the gap list is not read as a verdict on the whole system.

- **Audit log design.** HMAC-chained, fsynced, sequence-verified on open,
  device IDs keyed-hashed, no IPs, and — importantly — the servers **refuse to
  serve when the audit sink is unhealthy** rather than continuing silently. The
  carrier's terminal-class sealing (every post-redemption exit seals exactly one
  mutually exclusive outcome) is careful work.
- **Operational logging in `internal/bootstrap`.** Device IDs are excluded, the
  request ID is HMAC'd under a per-process random key, the record is
  schema-validated before emission, and it is dropped entirely if any device-ID
  alias (hex, four base64 variants) appears anywhere in it. That is more
  thorough than most production systems.
- **Anonymous-token mode.** Blind RSA tokens with a committed ephemeral ML-DSA
  key, durable single-use redemption, redemption strictly after
  proof-of-possession, issuer and carrier deliberately separated across trust
  domains.
- **v2 manifest trust state.** Rollback, equivocation, gap, and
  predecessor-digest checks, with explicit anti-TOFU bootstrap separation.
- **Metrics.** Aggregate-only, loopback-enforced, no per-user labels. I verified
  this on a live endpoint (T14/T15).
- **Fail-closed instincts throughout** — rate limiter, replay cache, schema
  version check, audit health, transparency-log lock after a crash.
- **Graceful shutdown** works and is sealed into the audit chain (T17).

---

## 5. Recommended order of work

1. **P0-1 probe resistance** — decide the cover-origin architecture. Nothing else
   matters if the endpoint is confirmed on first probe. Start by moving
   internet-facing carriers to anonymous-token mode, which removes the
   `certificate_authorities` leak for free.
2. **P0-2 revocation** — make the carrier consult a revocation source, or
   document loudly that revocation is control-plane only.
3. **P0-3 Postgres device IDs** — hash on write, add retention to `winn_peers`.
4. **P1-5 pre-auth limits** — `LimitListener` plus a per-IP connection cap on all
   three listeners; consider lowering `ReadHeaderTimeout` on the carrier.
5. **P1-6 / P1-7** — periodic manifest re-verification; durable cross-node replay
   store for identity mode.
6. **P2** — `securefile` ownership check on Unix, `.gitignore` key patterns,
   container image and CI.

---

## 6. Honest limits of this review

- I ran a **lab-mode carrier on loopback, on macOS**. I did not run the
  controller, the issuer, anonymous-token mode, a signed manifest, Postgres, or
  anything on Linux. A gateway I never started in its production configuration
  is a gateway I cannot vouch for, and the production configuration differs from
  what I tested in ways (manifest verification, anonymous auth, Postgres
  redemption) that matter.
- Probe-resistance findings T1–T8 are measured against the **lab TLS
  configuration**, which shares `internal/tlsconfig` with production. The
  discriminators are properties of that shared code, not of the lab PKI — except
  the `certificate_authorities` content, where the lab CA name stands in for the
  real one.
- Four other lanes were editing this tree concurrently. Findings reflect the tree
  as read on 2026-08-03.
- No performance, memory, or long-duration soak testing was done.
