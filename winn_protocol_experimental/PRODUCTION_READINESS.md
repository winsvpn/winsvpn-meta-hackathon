# Production Readiness Decision — Standalone Winn Protocol v3 (CORRECTED 2026-08-12)

**This file was corrected on 2026-08-12 by lane `doc_production_readiness`.** The previous version described **Winn v2** (internal/*, PostgreSQL, TLS1.3+ECH, AWG boundary) and was **FALSE when read as a claim about standalone Winn Protocol v3** (`winn_protocol_experimental/winn3/*`). See `docs/handoff/PRODUCTION_READINESS_AUDIT_20260812_doc_production_readiness.md` for the per-claim audit with measured grep evidence. That audit is the source of truth; this file summarizes its verdict.

**One-line verdict:** Standalone v3 cryptographic core and carrier/datapath scaffolding are implemented and gated by `winn3/conform` + `go test ./winn3/...`. **Full production (including gateway datapath descriptor resolver) is NOT READY** — the resolver interlock is deliberately held at `kWinn3DescriptorFormatVersion = 2` with `-resolver` off and forwarding unverified. Shipping the descriptor bump before verifying a live gateway responder would turn today's safe refusal into tomorrow's black-hole promotion. No high-assurance public claim without independent review.

---

## 0. What this document is and is not

- **Winn v2** lives in `internal/*`, `cmd/winn-*`, `scripts/verify.sh`, `deploy/*`, and uses TLS 1.3 + ECH + ML-DSA + PostgreSQL + systemd + AWG. Its readiness claims are not v3's.
- **Standalone Winn Protocol v3** lives in `winn_protocol_experimental/winn3/*` (`winn3/core`, `winn3/carrier`, `winn3/session`, `winn3/driver`, `winn3/tun`, `winn3/gateway`, `winn3/netlab`, `winn3/conform`, `datapath/`, plus runners `windows/runner/winn3_posture.h`, `linux/runner/linux_winn3_host.cc`, `apple/WinsTunnelCore/WinsWinn3*`, `android/.../WinnV3*`). Per `winn3/core/doc.go:1-5` it `has no dependency on AmneziaWG, on WireGuard, or on Xray, and it never will`. Per `_COMMON.md` the owner rejected relaying AmneziaWG datagrams (2026-08-08).
- A wrong doc is worse than no doc because it gets cited. This correction **never softens a claim the code fails to meet** — it marks it FALSE.

---

## 1. FALSE claims the previous document made about standalone v3 — read this first

Every row below was **measured** by two independent greps over `winn_protocol_experimental/winn3 --include="*.go"` and by reading the named symbol body (see handoff). `grep` hits quoted are MEASURED; `0` means not found by either term.

| Previous claim (about "Winn") | Verdict for standalone v3 | What the source actually says |
|---|---|---|
| Rekey reconciliation via `TunnelTransactionSource`, File/PostgreSQL `Prepare→Commit` serialization, `MaxConnections=1`, commit/rollback reconciliation from durable backend, latching hijack/poisoned release, Docker + real PostgreSQL + OpenSSL 3.5 + Windows DACL/reparse/handle + `verify.sh` interception matrix + `Open/Sync/Close` durability | **FALSE** | `grep -rn "TunnelTransactionSource\|postgres\|PostgreSQL" winn3 --include="*.go"` → 0. winn3 rekey is `winn3/core/params.go:132 RekeyAfterMessages=1<<28`, `142 RekeyAfterBytes=1<<36`, `winn3/core/index_test.go:94 Rekey(secret)`, and post-handshake ratchet `Session.MixPQ` (mixes ML-KEM-768 in-band, `core/doc.go:174`). No 2PC, no durable backend, no Docker/PostgreSQL gate. Failures are silent (`core/handshake.go:682`). |
| Hybrid secrecy: TLS 1.3 restricted to one ECDHE+ML-KEM group, no fallback/resumption | **FALSE** | `core/handshake.go` has no TLS handshake. Primitives are `Suite = winn3-x25519-mlkem768-chacha20poly1305-sha256` (`core/params.go:24`), with ChaChaPoly (`handshake.go:150`) and X25519; ML-KEM-768 is post-handshake ratchet not inside handshake (`core/doc.go:174-180`). `TLS 1.3` appears only as carrier overhead comment `carrier/sizing.go:54`. |
| ClientHello privacy: mandatory RFC 9849 ECH on controller/issuer/H3/H2, no downgrade | **FALSE** | `grep -rn "ECH\|echconfig\|EncryptedClientHello" winn3 --include="*.go"` → 0 (70 `mech/reach` substrings only). No `internal/echconfig` in winn3. |
| PQ authentication: per-request ML-DSA-65/87 + P-384 mTLS | **FALSE as worded** | Only gateway **descriptor** is ML-DSA-65-signed (`core/params.go:14`, `core/doc.go:186`, `core/handshake.go:260`). Client auth is X25519 static + optional 32-byte PSK (`handshake.go:52`), not per-request ML-DSA + mTLS. Two terms tried (`ML-DSA`, `mldsa`) both hit only descriptor. |
| Audience/identity: Controller audience, SPIFFE device SAN, peer/request/nonce binding | **FALSE** | `grep -rn "SPIFFE\|spiffe" winn3 --include="*.go"` → 0. winn3 binds `gateway_id` bytes to admission tag (`handshake.go:350`) and authenticates peer static via `accept` callback (`handshake.go:747`). |
| Replay/rollback: random request IDs/nonces, signature-independent digest, exact retry, monotonic generation | **FALSE as worded** | winn3 has `replayCache` (`handshake.go:701 SHA256 of body`) and `DefaultTokenWindow=1024` (`params.go:164`) with consume/force-advance, not request-ID/nonce scheme. `grep` for those terms → 0. |
| Secret generation: exactly 32 non-zero PSK bytes | **FALSE as worded** | `handshake.go:129` `if len(PSK)!=0 && len(PSK)!=32` — allows 0 or 32, no non-zero check (`grep non-zero` → 0). |
| Single-node / HA durability: AES-256-GCM, fsync/rename, COW rollback, OS lock; Serializable PostgreSQL + advisory locks | **FALSE** | `grep` for `AES-256-GCM\|fsync\|advisory` → 0. winn3 AEAD is `chacha20poly1305` (`handshake.go:150`), no file store. |
| Recovery: exact reapply/commit + pending abort (file & PostgreSQL) | **FALSE** | `grep reapply\|pending abort` → 0. |
| Revocation/key lifecycle: device revocation, expiry, overlapping PQ pins | **FALSE** | `grep revocation` → 0. Only overlap is gateway admission keys (`SetAdmissionKeys`, `handshake.go:628`) for rotation. |
| DoS: 32 KiB limits, bounded trust files, token buckets, max identities | **FALSE as worded** | Limits are `MaxHandshakeMessage=1024`, `MaxHandshakePayload=256`, `MaxAdmissionHMACs=64`, `MaxTagSize=32` (`params.go:66-127`), not 32 KiB. Token bucket exists only in `winn3/redteam/policy.go`/`winn3/gateway/guard.go` for test metering, not deployed DoS. |
| Audit: fsynced HMAC chain, keyed device IDs | **FALSE** | `grep "HMAC.*chain"` → 0. HMACs are per-packet admission tags, not audit chain. |
| Observability: loopback health/readiness/Prometheus | **FALSE** | `grep prometheus\|health.*readiness` → 0. Health is carrier-level `driver/dpbridge` assessment. |
| AWG boundary: no-shell absolute executable, restricted interface, private ephemeral PSK file | **FALSE** | `core/doc.go:4` `no dependency on AmneziaWG... never will`. winn3 does not manage AWG peers; only `driver/dpbridge/bridge.go:70 CarrierDirectAWG` as legacy plan value. |
| Deployment: systemd + PostgreSQL roles | **FALSE** | `grep systemd` → 0. No deploy units in `winn3/`. |
| Supply chain: `verify.sh` + `build_release.sh` + scanners as winn3 gate | **FALSE as gate** | `go.mod` pins (`circl v1.6.3` etc.) exist, but `scripts/verify.sh` gates `internal/*` (v2) with `docker info` + `postgres_test.sh`, not `winn3/*`. winn3 gate is `go test ./winn3/... -count=1` (see §4). |
| Trusted gateway discovery: expiry-bounded ML-DSA manifest + receipt chain + full inclusion + checkpoint | **FALSE as worded** | winn3 gateway identity is ML-DSA-65-signed descriptor (`core/params.go:14`), no manifest receipt chain (those are `internal/gatewaymanifest` etc., not `winn3/`). |
| Censorship path diversity: RFC 9298 H3 CONNECT-UDP + TLS H2 framed fallback | **FALSE** | `grep "CONNECT-UDP\|RFC 9298"` → 0. Diversity is `carrier.ClassUDP/TCP/TLS` with floor `carrier.Floor(...)` + `datapath`. |
| Carrier authorization: blind-token + ML-DSA proof | **FALSE** | `grep blind` → only `blind queue` in `carrier/pipe_test.go`. No privacy token. |
| Split-trust privacy: RFC 9474 blind RSA | **FALSE** | Same — 0. |
| Go/no-go #1 `scripts/verify.sh` | **FALSE for v3** | winn3 gate is not `verify.sh`; that script tests `internal/protocol` + `h3candidate` + `masque` + PostgreSQL (see `scripts/verify.sh:20-40`). |
| Go/no-go #3 "real AWG integration" | **FALSE for v3** | Standalone never uses AWG; `_COMMON.md` forbids fallback to AWG. |

Two rows are **PARTIALLY TRUE** as intended but false in the previous wording: algorithm diversity (X25519+ML-KEM-768 ratchet and ML-DSA-65 descriptor do exist per `params.go:24` and `doc.go:186`, but not X.509/SLH-DSA), traffic-shape (PadBucket/PadMimic + jittered retry exist per `params.go:238` and `driver/reconnect.go:30`, but not cover traffic), and network compatibility (adaptive inner MTU via `carrier/sizing.go`/`tun/mtu.go`/`session/pathmtu.go` exists, but not Happy Eyeballs/DNS64). Cross-platform build is **TRUE** (pinned guards for `windows/runner/winn3_posture.h`, `linux/runner/*`, `apple/WinsTunnelCore/*`, `android/.../WinnV3*` in `winn3/conform/conform.go:549-969`).

**If any claim above is cited as evidence for v3 readiness, it is a false-green citation.** See handoff for the command outputs that prove it.

---

## 2. What standalone v3 actually implements (release-gated today)

| Area | Implemented control (standalone v3) | Evidence (symbol, not line) |
|---|---|---|
| Wire | Two message classes only: `Handshake = AdmissionTag \|\| whitened(ephemeral\|\|sealed-static\|\|sealed-payload)` and `Transport = DemuxToken \|\| AEAD(frames\|\|padding)`. No cookie, no version, no length field. | `winn3/core/doc.go:29-38`, `winn3/core/handshake.go:289 WriteInitiation`, `797 WriteResponse` |
| Ciphersuite | No negotiation. `WireVersion = winn/3`, `Suite = winn3-x25519-mlkem768-chacha20poly1305-sha256`, `protocolLabel` in transcript. Hash = SHA256, KDF = HKDF-SHA256, DH = X25519, AEAD = ChaCha20Poly1305. | `winn3/core/params.go:16-30`, `winn3/core/keys.go` + `core/handshake.go:305 newChain` |
| Admission (cost boundary) | Tag is HMAC-SHA256 over `gateway_id` bytes + never-transmitted bucket + body whitening. First field, no extra packets, replaces mac1/mac2/cookie. `DefaultTagSize=32`, `MinTagSize=16`, `MaxTagSize=32`, `MaxAdmissionHMACs=64`, `DefaultBucketWindow=10s`, `DefaultMaxSkew=60s`. New responder with 5 keys at skew 32s refused; rotation via `SetAdmissionKeys` preserves replay cache. | `winn3/core/params.go:66-108, 200-314`, `winn3/core/admission.go`, `winn3/core/handshake.go:498 NewResponder`, `628 SetAdmissionKeys` |
| Handshake integrity | Sealed static + sealed payload under `h`-AAD (transcript commits to `protocolLabel`, responder static, ephemeral, sealed payloads). No admission input to `h`; deleting admission leaves core sound. | `winn3/core/doc.go:74-144`, `winn3/core/handshake.go:314-339` |
| Ephemeral codec | `Elligator2Codec` opt-in (indistinguishable), `DefaultEphemeralCodec` = identity (top-bit bias when admission stripped). Codec change binds wire output not point. | `winn3/core/doc.go:134-158`, `winn3/core/elligator.go`, `core/keys.go:158` |
| Silence | Every error is LOCAL, never signaled. Responder answers nothing on bad tag / replay / decrypt / identity. Only timing delta (HMAC vs X25519) exists and requires admission key. | `winn3/core/doc.go:159-172`, `winn3/core/handshake.go:670-688` |
| Forward/post-quantum | Gateway identity is ML-DSA-65-signed descriptor out of band (design doc). Confidentiality hybrid: ML-KEM-768 mixed post-handshake via `Session.MixPQ` in-band ratchet, not in handshake (fits 1280 MTU). X25519 auth known weakness recorded. | `winn3/core/doc.go:173-188`, `winn3/core/params.go:22`, `winn3/core/transcript.go:51 labelRekey`, `core/session.go: MixPQ` |
| Handshake geometry | `MaxHandshakePayload=256`, `MaxHandshakeMessage=1024` (<1280 so no frag), `handshakePayloadHeaderSize=3` (flags 0 + len BE16 inside AEAD). Padding via `PadAuto` (spread 256, uniform, modulo bias 2^-56) or explicit `padTo`. | `winn3/core/params.go:113-128`, `winn3/core/handshake.go:181-239` |
| Transport | `DefaultTokenWindow=1024`, `Min=16`, `Max=1<<16`, `CallerOwnsTokenWindow=-1` (global index). Nonce = 4-byte salt + 8-byte BE counter (`AEADNonceSize=12`). `RekeyAfterMessages=1<<28`, `RekeyAfterBytes=1<<36`, `RejectAfterMessages=(1<<32)-(1<<16)`. `PaddingPolicy: PadDefault→PadBucket (default), PadNone (opt-in, leaks), PadMimic`. | `winn3/core/params.go:130-246`, `winn3/core/session.go`, `winn3/core/replay.go` |
| Sizing / MTU | Plan floor = `carrier.Floor(pathMTU, UDP, TCP, TLS)` (84 bytes below dialled UDP/IPv4). `DefaultPathMTU` fleet default (was 1280, now 1450 per `conform/conform.go:290`). Path MTU **negotiated on refusal** (`DecodePathMTUNotice` in `winn3/session/pathmtu.go`, `NegotiatedPathMTU`) and pinned by `TestTheShippingGatewayEmitsThePathMTUNoticeOverARealSocket`; applying negotiated min to live tunnel is deliberately **not shipped** — ends must still be configured identically. | `winn3/carrier/sizing.go`, `winn3/driver.NewSizing`, `winn3/tun/mtu.go`, `winn3/session/pathmtu.go`, `winn3/conform/conform.go:27-38` |
| Carrier & migration | Carriers are bounded-byte-string movers: `carrier.ClassUDP`, `ClassTCP`, `ClassTLS` (and `CarrierDirectAWG` legacy plan value). Backoff is exponential-full-jitter with hard attempt cap (`winn3/driver/reconnect.go:30 Backoff`, `winn3/carrier.Backoff`); migrating carrier class rather than another retry. MTU floor already captures migration cost. | `winn3/carrier/*`, `winn3/driver/reconnect.go`, `winn3/conform/conform.go:156-184` |
| Fail-closed posture | Promotion installs `0.0.0.0/1+128.0.0.0/1` (beats existing default without deleting it) and for v6 the `/1` pair; `VerifyPromotedPostureCaptures` + `VerifyPromotedCommandsCapture` both required (caught by `conformance.go:549-630`). `enforceRoutes=true` + `/32` `excludedRoutes` on Apple is the "protect" (`conformance.go:631-677`). Empty resolver = refused (`conformance.go:679-905`). | `winn3/tun/tun.go`, `winn3/tun/gate.go`, `windows/runner/winn3_posture.h`, `linux/runner/*`, `apple/WinsTunnelCore/WinsWinn3SessionStart.swift`, `android/.../WinnV3Posture.kt`, `winn3/conform/conform.go:531-905` |
| Resolver (NOT READY) | Mobile derivation `WinsWinn3Resolvers` (Apple) / `WinnV3Resolvers` (Android) derives `innerResolver = signed inner_resolver_v4` conditioned on next-hop (`is the next hop AND the signed descriptor names no resolver there` narrowed 2026-08-12). Replaces rather than joins public DNS. Desktop stores but does NOT consume `inner_resolver_v4` (still needs derivation). Gateway responder `cmd/winn3-gateway/resolve.go` off by default; interface is `winn3/tun`-validated (source must be own assignment). | `winn3/conform/conform.go:746-969`, `apple/WinsTunnelCore/WinsWinn3SessionStart.swift: enum WinsWinn3Resolvers`, `android/.../WinnV3Posture.kt: WinnV3Resolvers`, `cmd/winn3-gateway/main.go: -resolver`, `cmd/winn3-gateway/resolve.go` |
| Cross-platform | Linux/macOS/Windows/server + Android client builds via same `winn3/conform` suite. Every host parsed the same `[winn]` INI fixture (`ServedWinnSectionINI`) and derivations must `MustMatch`. | `winn3/conform/conform.go:95-531`, `go list ./winn3/...` |

---

## 3. Gateway datapath descriptor resolver — the blocking gap (MEASURED)

**Status: NOT production ready. Do not claim it.**

- `winn3/conform/conform.go:488` MEASURED: `derivation. There is no v3 resolver anywhere in the system: the ML-DSA-65 descriptor's closed field set has none, the hub serves none, and cmd/winn3-gateway's own source says it "forwards nothing, resolves nothing and egresses nothing"`.
- `winn3/conform/conform.go:928` `StandaloneResolverStagingGuards` pin **inertness**:
  1. `lib/winn_protocol_dispatch.dart: const int kWinn3DescriptorFormatVersion = 2;` — **ADVERTISEMENT INTERLOCK**. Control plane is at 3 with `inner_resolver_v4` in REQUIRED set; client deliberately stays at 2 so v3 descriptor fails `descriptor-unsupported-format-version` and node serves `winn/1`. Bumping is the **LAST** step.
  2. `lib/winn_protocol_dispatch.dart: if (descriptor.innerResolverV4.isNotEmpty)` — line emitted **only** when verified descriptor carries field.
  3. `linux/runner/linux_winn3_host.cc: } else if (key == "inner_resolver_v4") {` and `windows/runner/winn3_supervisor.h: } else if (served && key == "inner_resolver_v4") {` — keys are **KNOWN** (so bump does not refuse whole config) but **stored not consumed** on desktop.
- `cmd/winn3-gateway/resolve.go` exists (795 lines, `resolve_tcp.go`) but `conform.go:915` `has never answered a query on a real node`; `cmd/winn3-gateway/main.go:575` `"-resolver is on: answering DNS at %s:53"` — flag is **off by default**.
- `winn3/conform/conform.go:918-923` — if a descriptor advertises `inner_resolver_v4` before responder + forwarding are verified live, all four hosts stop refusing and promote GREEN with routes moved and DNS pointing at an inner address where **nothing listens** → names fail or, with `-forward` unverified, TCP black-holes while UI reads Connected. Staging guards exist so that removal is ordered with live evidence, not config.

**What would close it (in order, each removal is a shipped change, not a doc edit):**
1. `cmd/winn3-gateway -resolver` answering on a **real node** at its own `-inner-v4`, with `tun` validator proven (source == own assignment) and TCP/UDP 53, forwarding verified end-to-end, stats `resolverStats`.
2. Desktop derivation for `inner_resolver_v4` (mirror of Apple/Android `WinsWinn3Resolvers`), wiring stored value into `BuildPromotedPosture` (not copying `dns_are_inner` boolean).
3. Bump `kWinn3DescriptorFormatVersion` 2→3 in `lib/winn_protocol_dispatch.dart` **together with** 1+2.

Until then, deployed v3 promotes with **no resolver moved** on desktop (refused) and with **correct derived** inner resolver only on mobile — both fail-closed, which is the safe posture, but not a production data path for name resolution. The gateway **datapath** (carrying `DemuxToken||AEAD(frames)` via `winn3/tun` + `winn3/session` over `datapath/`) **does carry** once handshake succeeds (proven via `winn3/driver`, `winn3/netlab` socketpair/loopback rigs), but **name resolution through it does not** without the above.

---

## 4. Go/no-go rule for standalone v3 (replaces v2 `scripts/verify.sh` gate)

Go for a controlled deployment **only when**:

1. `go vet ./winn3/...` and `go test ./winn3/... -count=1 -race` pass on the promoted source/toolchain (not `scripts/verify.sh`, which gates `internal/*` v2). Pin: `winn3/conform` + `TestEveryPinNamesATestThatExists` + all `Standalone*Guards` greps green (each `Needle` occurs exactly once via `winn3/conform/conform_test.go`).
2. Release checksums/SBOM are archived and provenance is verified (deterministic build via `scripts/reproducible_build_test.sh` for root, plus winn3 binary checksums; no hash-assert on staged `.so` — assert **symbol presence**).
3. **Physical datapath promotion** passes: `VerifyPromotedPostureCaptures` + `VerifyPromotedCommandsCapture` on each shipping OS (`windows/runner/winn3_posture.h`, `linux/runner/*`, `apple/WinsTunnelCore/*`, `android/...`) plus a real new-socket H3/TLS migration or carrier escalation without re-handshake (`winn3/tun/tun_test.go: tlsCarrier`, `winn3/driver/escalation_test.go`).
4. **Handshake / rekey / the three silent-refusal fixes** pinned: `gateway_id` raw bytes (`winn3/conform.Operator.GatewayIDBytes`), admission secret trimmed opacity (`AdmissionSecret`), and path-MTU notice (`session/pathmtu.go: DecodePathMTUNotice`) all green — `winn3/conform`'s `Derivation.MustMatch` over the single `Reference()` operator at `pathMTU=1500` over `udp,tcp,tls`.
5. All deployment-owner gates marked mandatory by the service risk owner have accountable sign-off (see §5 — AWG/ECH/blind-token/manifest-checkpoint gates are **N/A for standalone** and must not be treated as go/no-go).

No-go on any: wrong Suite/WireVersion (`winn3/core/params.go:19 Suite`) causing transcript mismatch, admission tag verification failure, replay cache miss (silent), `ErrCallerOwnsWindow` misconfiguration (`params.go:194`), `a promotion that would install NO resolver is refused` (conform `StandaloneResolverGuards`), fail-open routing (missing `VerifyPromotedPostureCaptures`), expired descriptor / ML-DSA-65 signature failure, `RekeyAfter*` ceiling exceeded (`ErrCounterExhausted`), or unresolved reachable `govulncheck` finding in `circl`/`quic-go`/`pgx` pins.

Developer skips (`-short` etc.) and Windows cross-compilation alone are **not** release evidence — same gate as before, now applied to `winn3/*`.

---

## 5. Deployment-owner gates — what still applies to standalone v3

These cannot be completed generically inside `winn_protocol_experimental/`; the service risk owner marks which are mandatory. For standalone v3, **strikethrough = not a gate for this protocol** (do NOT treat as must-pass, do NOT deploy a control that mimics it):

| Gate | Minimum for standalone v3 | Verdict vs previous wording |
|---|---|---|
| Independent security review | External cryptographer/protocol engineer reviews the **v3** spec (`docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md`), canonicalization (`winn3/core/params.go`, `core/handshake.go` `handshakePayloadHeaderSize`), state machine (`winn3/session/*`, `winn3/driver`, `winn3/tun`), CIRCL use (`chacha20poly1305`, `sha256`, `hmac`), and deployment. | Replaces "reviews the v2 spec" |
| Production CA/enrollment | Authenticated issuance for gateway static keys, **ML-DSA-65 descriptor publishing** (signer custody, overlap, expiry automation, recovery drilled). `winn3/core/keys.go` generation + `cmd/winn3-gateway -gateway-id` naming. | Keeps |
| State/audit key custody | **N/A** — no durable state/audit file/PostgreSQL in v3 (ephemeral `Session` + `replayCache` per gateway). Custody is for admission keys and PSKs: generation via `crypto/rand`, rotation via `SetAdmissionKeys` (overlap 2), install via descriptor re-sign. | Was v2 file/HSM gate — FALSE for v3 |
| Registry/pin distribution | Signed/controlled enrollment workflow prevents filesystem substitution of **ML-DSA-65 descriptor** and `winn3` branch trust roots. | Keeps |
| Real AWG integration | **N/A — MUST NOT** | Was v2. `_COMMON.md` + `core/doc.go:4` forbid solving v3 with AWG/Xray. |
| OS network-change integration | Android/iOS/macOS/Windows/Linux adapters signal validated network changes and keep native kill switch active while winn3 replaces carriers (`winn3/driver/reconnect.go` jittered backoff, `winn3/tun/gate.go`). | Keeps |
| ECH lifecycle | **N/A** | No ECH in v3. |
| Manifest transparency governance | **N/A as worded** — replaced by **descriptor format governance**: independent descriptor publication/retention, signer custody, `inner_resolver_v4` sequence/expiry, split-view monitoring, emergency rollback of format 3, as pinned by `StandaloneResolverStagingGuards`. | Was v2 `gatewaymanifest` receipt chain |
| Blind-token operations | **N/A** | No privacy token in v3. |
| Carrier edge deployment | UDP/TCP 443 reachability for `cmd/winn3-gateway` listeners, **no fixed backend ACL** (v3 has no carrier backend), gateway `resolve.go` load/soak if resolver enabled, node draining, egress-identity policy, abuse alerts (`winn3/gateway/guard.go` token bucket). | Replaces QUIC/H2 + fixed backend |
| HA/failover | Staging load, **gateway** failover, network partition, backup/PITR **not applicable** (no DB), multi-instance `replayCache` / `Mux` aggregation. | Keeps without DB |
| Edge availability | Firewall/load-balancer SYN + TLS controls, capacity plan, abuse thresholds, DDoS response. | Keeps |
| Monitoring/on-call | Metrics collection, expiry dashboards (`RekeyAfter*` exposure), alerts, runbooks, accountable responders. | Keeps |
| Release provenance | Trusted build workers, reviewed commit, artifact retention, independent public release pin, optional **offline SLH-DSA** via `scripts/sign_release_slhdsa.sh` (algorithm diversity per §2). | Keeps |
| Compliance/privacy | Required FIPS validation **if applicable** — `cloudflare/circl` implements the algorithms but `is not automatically a FIPS 140 validated module` (`go.mod: circl v1.6.3`) — choose approved boundary. Device-identifier privacy, log retention, regional review. | Keeps note |
| Long-duration assurance | CI fuzzing (`winn3/core/fuzz_decode_test.go`), race tests (`go test -race ./winn3/...`), `gosec`/`govulncheck` via `scripts/scanner_matrix.sh` adapted to `winn3/*`, soak/load, periodic disaster drills. | Keeps |

---

## 6. Provenance and how to verify this correction

- Backup of the previous (v2) file: `winn_protocol_experimental/PRODUCTION_READINESS.md.bak_20260812_doc_production_readiness` (`sha256 e932402960da42428bde7790414e0ae243ed6d5f69801b297089fa76ed66f5a1`).
- Audit that justifies this correction: `docs/handoff/PRODUCTION_READINESS_AUDIT_20260812_doc_production_readiness.md` — every TRUE/FALSE/UNVERIFIABLE there quotes the grep and the symbol; no invented path, symbol, or count.
- To re-verify: `grep -rn "ECH\|TunnelTransactionSource\|SPIFFE\|systemd\|blind" winn_protocol_experimental/winn3 --include="*.go"` must remain 0; `grep -rn "There is no v3 resolver anywhere" winn_protocol_experimental/winn3/conform/conform.go` must remain 1; `go test ./winn3/... -count=1` (no cache) must be green before any ship claim.

**Never weaken a gate to make something pass. If a test is wrong, say so; do not neuter it. A wrong doc is worse than no doc because it gets cited.**
