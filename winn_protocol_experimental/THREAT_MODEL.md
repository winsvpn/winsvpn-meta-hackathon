# Winn Protocol v3 — Standalone Datapath Threat Model

> **Status 2026-08-12 (doc_threat_model lane):** This file was `Winn Protocol v2` (192 lines). It is stale for the lane goal `production-ready STANDALONE Winn Protocol v3`. The v2 file is preserved as `THREAT_MODEL.md.bak_20260812_doc_threat_model` and as `THREAT_MODEL_V2_HISTORICAL.md` (if present). Every claim below was audited against `winn3/*` source; FALSE claims were not softened. See `docs/handoff/THREAT_MODEL_AUDIT_20260812_doc_threat_model.md` for the per-claim TRUE/FALSE/UNVERIFIABLE table (23 FALSE, 11 UNVERIFIABLE, 8 TRUE of 42 atomic claims).

## Scope

- **In scope:** `winn3/core` (handshake, key schedule, transport crypto), `winn3/gateway` (dispatch, token index, admission metering, eviction), `winn3/session` (frame-level driver, rekey, liveness, padding, path-MTU negotiation), `winn3/driver` (loop joining session+tun+carrier), `winn3/tun` (fail-closed tunnel, gate, validator, MTU), `winn3/carrier` (Pipe UDP/TCP/TLS, sizing floor), `winn3/conform` PostureGuards (resolver/mtu/gate invariants).
- **Out of scope for this datapath doc (v2 historical, now separate):** Winn v2 controller state (PostgreSQL, generation/pending-request transactions, HA advisory locks), AWG backend + sentinel-mapped carrier-to-AWG, ECH, X.509+ML-DSA rotation, blind-token issuance, gateway-manifest transparency log, QUIC multipath. Those live in the control-plane / v2 threat model, not in `winn3/*`. This doc never claims they are handled on the datapath.

## Assets (standalone v3)

- Long-term X25519 static key pairs (client + gateway). Private scalar 32 bytes (`winn3/core/keys.go:16-73` `StaticKey`, `GenerateStaticKeyFrom` reads exactly 32 bytes). Public half distributed via **ML-DSA-65-signed descriptor from the control plane** (`core/handshake.go:258`, `keys.go:18`, `session/config.go:274`). The descriptor is the supply-chain input; verification of it is not in `winn3/*`.
- Per-session X25519 ephemeral keys (handshake + ratchets) and per-direction handshake chain keys (`core/handshake.go:305-357`).
- Per-gateway admission secrets `GatewayParams.AdmissionKeys` + `GatewayID` + `TagSize` + `Freshness` (bucket window + skew) — `core/params.go:316-372`. `MaxAdmissionHMACs=64` bounds reject-path HMACs (`core/params.go:107`).
- Post-quantum ML-KEM-768 shared secret and encapsulation key / ciphertext (1184/1088 bytes) — `core/session.go:44-48, 429-467` `GeneratePQEphemeral`, `PQEncapsulate`, `MixPQ`.
- Per-direction transport keys, nonce salts, demux keys (`core/session.go:52-77`), demux tokens (PRF 8 bytes `core/params.go:59`, `replay.go:141`), token-window replay filter (`core/replay.go:175-321`).
- Path-MTU agreement state: responder notice (`session/pathmtu.go:98-127` 7-byte `W3PM` v1 record, mtu uint16 BE) and negotiated min.
- Gateway token-index budget and per-session forward windows (`gateway/params.go:58-70`, `table.go:75-76` `liveTokens`/`budget`, `entry.go:48-66`).
- Inner IP assignment (`tun/validator.go` `Assignment`: inner_v4/v6, router_v4/v6, resolver) and interface MTU (`tun/tun.go:305-331` `InnerMTU`, `CarrierFloorMessageSize`).

**Not assets of this datapath (v2 historical):** AWG per-peer PSKs, TLS private keys, ML-DSA seeds, PostgreSQL credentials, state-encryption/audit keys, ECH keys, gateway-manifest/receipt keys, blind-token issuer keys. Those were v2 controller assets; citing them for v3 decisions produces misrouting (same class as silent-refusal instance #3).

## Security goals — standalone v3

Winn v3 standalone is designed to:

- **Hybrid confidentiality:** X25519 + ML-KEM-768 mixed into the chain; breaking one does not expose traffic of symmetric epochs (`core/params.go:21` `Suite`, `session.go:375 MixPQ` in-band ratchet after strict handshake). Authentication remains X25519; gateway identity is post-quantum via out-of-band ML-DSA descriptor.
- **No negotiable downgrade:** single `Suite` `winn3-x25519-mlkem768-chacha20poly1305-sha256` never on the wire, transcript-bound (`core/params.go:8-15`, `handshake.go:186` flags must be zero else `ErrDecrypt`).
- **Cost-bounded silently-rejecting front door:** unauthenticated datagram cost is a shard-local map lookup + bounded HMACs, no allocation, no reply, ever (`gateway/gateway.go:240-325` `Handle` order length→index→metered admission, `guard.go:39-94` fixed 4096-cell maphash meter, `core/params.go:107` ceiling 64). No cookie, no error datagram — a cookie is a probe oracle.
- **Exact replay / reordering duality:** handshake replay cache `core/replay.go:66 lifetime=(2*spread+1)*window`, transport `tokenWindow` simultaneous demux + exact replay filter + reordering tolerance `size/2-1` (`replay.go:262-296`).
- **Fail-closed tunnel:** `tun/tun.go:504` takes gate before any parse; `gate.go` latches closed; `Stats RxPackets` only counts `RxDeviceWrites` if `DeviceProven` (`tun/tun.go:440-493` — false-promotion fix; without it `sendto` to dead 127.0.0.1 port count moves with no delivery).
- **Detect silent MTU mismatch, not hide it:** responder states planning path MTU (`gateway/gateway.go:155-158` `EncodePathMTUNotice`, `session/pathmtu.go:110`), initiator compares via `NegotiatedPathMTU` min and either shrinks (`ShrinkToPeerPathMTU`) paired with `tun.ClampInnerMTU` before gate opens, or refuses loud (`session/driver.go:895-928` `refusePathMTUMismatch`, `gateway/params.go:198-373` dead-zone 1280-1420 refused).
- **No precomputation without proof:** initial window `DefaultInitialWindow=32` (`gateway/params.go:27`), growth earned by opening messages (`entry.go:233-261` `maybeGrowLocked` doubled against budget).
- **Inner-packet correctness:** family/ martian / source-not-ours / reflected / oversize checks (`tun/validator.go`), `InnerMTU` derived from carrier floor across all migration classes (`driver/doc.go:65-81`), truncation adaptation via synthesised `PTB`.
- **Resolver confinement:** promotion refused if no `inner_resolver_v4` or resolver not inside tunnel (`conform/conform.go:679-773` `StandaloneResolverGuards`; mobile/desktop commission vs omission split).
- **Unlinkable, non-metronomic timing:** truncated-exponential silence/probe/rekey draws (`session/config.go:38-113` `Draw`, `jitter.go`), in-band rekey/PQ ratchet inside current AEAD (no recurring handshake packet).

Explicitly **not goals** of the datapath (and must not be claimed as such): ECH hiding of inner ClientHello (no ECH in `winn3/*`), gateway-manifest transparency, PostgreSQL HA serialization, QUIC multipath, blind-token unlinkability, Xray/AWG cryptanalysis.

## Adversaries considered

- Passive collector (harvest-now-decrypt-later) on control-plane + carrier.
- Active network attacker: intercept / replay / reorder / drop / inject / redirect / delay, including wholesale UDP block (the measured 24-retries-100% loss case `session/config.go:105-109`).
- Future quantum attacker breaking ECDSA/ECDH but not ML-KEM/ML-DSA.
- Authenticated enrolled peer flooding CPU/memory, or holding many sessions.
- Off-path injector copying observed demux tokens or spraying handshake-sized garbage.
- Local observer reading carrier IP, timing, volume, packet sizes, carrier fingerprint (TLS/QUIC) — see residual risks.

## Trust boundaries (standalone)

1. **Network → Admission:** tag authenticates version/tagLen/bucket/gwID/body under per-gateway key, never transmits bucket (`core/admission.go:63,110-133` `bucketIndex`, `verifyAdmission`). Length bounds leak no key info (`admission.go:167-173` `ErrShortMessage`/`ErrLongMessage`).
2. **Admission → Core crypto:** admission contributes *nothing* to integrity; strip it and inner AEADs still fail (`core/doc.go:79-132` non-goal invariant). Rotation via `Responder.SetAdmissionKeys` preserves replay cache; rebuilding Responder would reopen a replay clock (`handshake.go:581-626`).
3. **Handshake:** X25519 es/ss + ee/se derivation, optional PSK mix, `sealStage`/`openStage` ChaCha20-Poly1305 with nonce zero per stage, AAD = transcript h (`handshake.go:282-457`). `flags` reserved zero.
4. **Transport:** `Seal`/`Open` with demux token AAD, nonce salt+counter, inner payloadLen field (`session.go:242-349`), `ErrDecrypt` vs `ErrUnauthenticated` separation.
5. **Gateway dispatch:** sharded token index `table.go:144-150` leading-byte uniform, `Dispatch` `ErrSession` vs `ErrNoRoute` not collapsed (`table.go:477-508`, `gateway.go:250-253` fallthrough guard).
6. **Tun gate:** fail-closed authority `tun/tun.go:504` + `gate.exclude` for `ClampInnerMTU` drain barrier (`tun/tun.go:402-431`).
7. **Path-MTU:** wire notice `W3PM` v1 inside handshake payload (`session/pathmtu.go:88-104`), arithmetic `NegotiatedPathMTU` min + apply guard `ShrinkToPeerPathMTU` (`pathmtu.go:187-235`).
8. **Resolver/posture:** `winn3/conform` PostureGuards enforce resolver, mtu, gate invariants before promotion (`conform.go:397-852`).

Historical v2 boundaries removed: mandatory ECH, SPIFFE URI SAN equality, Winn→PQ registry lookup, generation transaction, state→AWG adapter, PG TLS + encrypted envelopes, HMAC-chained audit, carrier→AWG sentinel, discovery→inclusion proof, blind-token proof.

## Important attack outcomes (standalone)

| Attack | Expected outcome | Where |
|---|---|---|
| Wrong admission key, gateway ID, or clock outside `(2*spread+1)*window` | `ErrUnauthenticated`, silent, no reply; `gateway.Stats.Unauthenticated` increments | `core/admission.go:195`, `gateway/gateway.go:272` |
| Structural length `len<=tagLen` or `len>MaxHandshakeMessage` | `ErrShortMessage` / `ErrLongMessage` before HMACs, still silent to peer | `admission.go:167-173` |
| Replay of a seen initiation body | `ErrReplay` via `replayCache.seen` + `remember` only after crypto, silent | `handshake.go:702-774` |
| Ciphertext bit flip, wrong X25519 point, tampered payload header | `ErrDecrypt` / `ErrPeerIdentity`, silent | `handshake.go:738-769`, `keys.go:113 low-order reject` |
| Unknown demux token | `ErrUnauthenticated`, `Table.Stats.Missed`, silent | `session.go:302`, `table.go:486` |
| Known token, AEAD fails (forgery/corruption) | `ErrDecrypt`, `ErrSession` (not `ErrNoRoute`), does NOT fall through to admission | `session.go:331`, `table.go:507`, `gateway.go:250-253` |
| Burst loss > window (implicit counter desync) | **Not** error-count teardown; size-aware probe detection: wide/narrow ladders → `PathNarrowedFor` or `ErrPeerUnreachable` after `MaxLostProbes` with `!heardSince` | `session/driver.go:1157-1291` (never error-driven) |
| Path-MTU mismatch where both ends claimed and min is in dead zone 1280-1420 | `ErrPathMTUMismatch` loud to operator, session `StateFailed` | `session/pathmtu.go:273`, `gateway/params.go:198` |
| Oversized inner packet > InnerMTU | `ErrOversize` drop + synthesised PTB inbound at rate limit | `tun/tun.go:518-594`, `pmtuTokenBucket` |
| Promotion without resolver / v1-shaped resolver / resolver outside tunnel | Promotion refused (`StandaloneResolverGuards`) | `conform/conform.go:679-852` |
| Off-path spray of handshake garbage | Rate-gated `admitReinitiation` at most once per `reinitCheckInterval` (1 ms) beyond one AEAD | `session/driver.go:787-869` |
| Token collision (64-bit birthday) | Overflow list bounded `maxCandidates=4`, one extra AEAD | `table.go:31`, `entry.go:189` |

Removed (v2 historical, now false if claimed for standalone): `Classical-only TLS client → no group`, `Wrong ML-DSA seed → pq_auth_rejected`, `Second file controller → exclusive lock`, `HA PostgreSQL serialization`, `CONNECT-UDP sentinel mismatch`, `QUIC path validation`, `blind-token replay`, `discovery transparency` — none implemented in `winn3/*`.

## Residual risks and non-goals (standalone)

- Compromise of device kernel, Go runtime, CA store, controller host, or protected key store.
- Attacker holding gateway static private + admission keys (cost boundary bypass — still silent to unauthenticated path).
- Gateway static compromise → client impersonation to real gateway is mitigated only if `RequirePSK` true (`handshake.go:55-68`); default off until per-subscriber PSK wired — document, do not claim.
- Traffic correlation: carrier IP, carrier fingerprint, endpoints, timing, volume, packet sizes (unless `PadBucket`/`PadMimic`) remain observable; not browser-indistinguishable (`core/params.go:212-247`).
- DoS before admission limiter — gateway-wide + per-source meter is the edge, not TLS SYN.
- Replay window reopens on gateway restart (in-memory only, `replay.go:35`).
- `ApplyNegotiatedPathMTU` shrink must pair with `tun.ClampInnerMTU` before gate opens; device without `MTUSetter` stays loud refusal.
- Platform tunnel traps: `tun.Overhead=29`, `MinCarrierMessageForIPv6`, and kernel `ipv6_add_dev -EINVAL` below 1280 cause dead-zone refusal — `driver/sizing.go` plan floor refuses 1280-1420.

## Operational assumptions (standalone)

- Every peer has unique 32-byte X25519 static; gateway public distributed via authenticated ML-DSA-65-signed descriptor supply chain.
- Every gateway has `GatewayID` non-empty ≤255 bytes and `TagSize` in `[16,32]` (`core/params.go:347-372`), `Freshness` window ≥1s and `skew ≥ window` (`params.go:303-314`, `admission.go:114-133`). Spread `=ceil(skew/window)`, reject cost `nKeys*(2*spread+1) ≤64`.
- `MaxMessageSize` is the **plan floor** across every carrier class the session may escalate to, not the dialled carrier (`driver/doc.go:65-81`, `session/config.go:495`). `MessageFloor = TransportOverhead + frameHeaderSize`.
- `CarrierFloorMessageSize` leaves `InnerMTU ≥1280` when inner v6 assigned (`tun/tun.go:312`), and `DeviceMTU ≤ InnerMTU` (`tun/tun.go:327`).
- Liveness draws are truncated-exponential, no fixed 25.000 s metronome (`session/jitter.go`, `driver/doc.go:65-81`).
- Handshake retransmission is exponential full-jitter with `FreshAfter=2` fresh ephemerals (`session/driver.go:397-432` `DefaultFreshAfter`, `handshakeBudget` + cap).
- Clocks, cert/registry lifecycle, descriptor rotation, and metrics/audit retention are actively operated.

## References

- `winn3/core/doc.go`, `keys.go`, `params.go`, `admission.go`, `handshake.go`, `session.go`, `replay.go`
- `winn3/gateway/doc.go`, `params.go`, `gateway.go`, `guard.go`, `table.go`, `entry.go`, `token.go`
- `winn3/session/doc.go`, `config.go`, `pathmtu.go`, `driver.go`, `padding.go`, `jitter.go`
- `winn3/tun/tun.go`, `gate.go`, `validator.go`, `mtu.go`
- `winn3/carrier/carrier.go`, `sizing.go`, `migrate.go`, `stream.go`, `udp.go`
- `winn3/driver/doc.go`, `loop.go`, `params.go`, `sizing.go`
- `winn3/conform/conform.go` `StandaloneResolverGuards` + `StandaloneMobileResolverGuards`
- Audit: `docs/handoff/THREAT_MODEL_AUDIT_20260812_doc_threat_model.md`
- Prior v2: `THREAT_MODEL.md.bak_20260812_doc_threat_model`
