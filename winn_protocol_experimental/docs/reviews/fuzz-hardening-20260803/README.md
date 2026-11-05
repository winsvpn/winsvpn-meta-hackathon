# Winn Protocol v3 — Fuzz Hardening Report

**Date:** 2026-08-03
**Scope:** `winsvpn.local/winnprotocol`, Go 1.26.5, darwin/arm64, 18 cores
**Purpose:** Pre-audit hardening against hostile network input.

Threat model assumed throughout: a national-scale adversary running deep packet
inspection and **active probing**. Every byte the protocol accepts from the
network is attacker-controlled. A crash that fingerprints the client is a safety
failure, not merely a bug.

---

## 1. Summary

| | |
|---|---|
| Fuzz targets before this work | 11 (the brief said 8; see note below) |
| Fuzz targets after this work | 24 |
| Fuzz time, cumulative per-target | 4 h 55 m (11 × 15 m + 13 × 10 m) |
| Fuzz time, wall clock | ~1 h 25 m (4 lanes in parallel) |
| Fuzz time, CPU | ~19 h 40 m (4 workers per target) |
| Crashers found | **1** |
| Crashers fixed | 1, with 4 regression tests |
| Dependency advisories | 0 affecting this module (`govulncheck` clean) |
| Baselines | `go build ./...`, `go vet ./...`, `go test ./...` (66 pkgs) all pass |

**Note on the pre-existing target count.** The brief listed 8 existing targets.
There were in fact **11**: the brief omitted `FuzzValidateRequest`,
`FuzzValidateResponse` (both `internal/protocol`) and
`FuzzVerifyMLDSASignatureEncoding` (`internal/pqauth`). It also named
`FuzzSignatureHeader` and `FuzzInspect*` correctly. All 11 were run.

**The single crasher is a genuine unauthenticated remote panic** in a third-party
dependency, reachable from both the server-side CONNECT-UDP parser and the
client-side proxy-response parser. `govulncheck` does not know about it — it is
not in any advisory database. Details in Finding F-1.

---

## 2. Findings

### F-1 — Unauthenticated remote panic via RFC 9651 Structured Fields parser (FIXED)

**Severity:** High. Unauthenticated remote denial of service; on the client side
also a fingerprint.

**Where:** `github.com/dunglas/httpsfv@v1.1.0`, reached from
- `internal/masque/proxy_request.go:67` — `Capsule-Protocol` request header, server side
- `internal/masque/client.go:94` — `Proxy-Status` response header, client side

**Found by:** `FuzzParseProxyRequest` (new target), after 3 seconds of fuzzing.

**Reproducer:** `internal/masque/testdata/fuzz/FuzzParseProxyRequest/4b666cba41d1b91e`

```
go test fuzz v1
string("CONNECT")
string("connect-udp")
string("proxy.example.com")
string("0")
string("@")
```

The last field is the `Capsule-Protocol` header value: a single `@`.

**Root cause.** `parseNumber` calls `isNeg` before performing its own EOF check,
and `isNeg` dereferences the scanner buffer unconditionally:

```go
// httpsfv@v1.1.0/integer.go:95
func isNeg(s *scanner) bool { if s.data[s.off] == '-' {   // <-- no bounds check

// httpsfv@v1.1.0/integer.go:40
neg := isNeg(s)
if neg && s.eof() { ... }                                 // <-- check comes after
```

`parseDate` consumes the `@` Date marker, advancing `s.off` to the end of the
buffer, then calls `parseNumber`. Any value whose final character is `@` panics.

**Observed panic:**

```
panic: runtime error: index out of range [1] with length 1
github.com/dunglas/httpsfv.isNeg(...)          integer.go:95
github.com/dunglas/httpsfv.parseNumber(...)    integer.go:40
github.com/dunglas/httpsfv.parseDate(...)      date.go:30
github.com/dunglas/httpsfv.parseBareItem(...)  bareitem.go:105
github.com/dunglas/httpsfv.parseItem(...)      item.go:62
github.com/dunglas/httpsfv.UnmarshalItem(...)  item.go:47
winsvpn.local/winnprotocol/internal/masque.ParseProxyRequest(...) proxy_request.go:67
```

**Confirmed triggering values** (probed directly against the dependency):

| Value | Result |
|---|---|
| `@` | **panic** — index out of range [1] with length 1 |
| `1;a=@` | **panic** — index out of range [5] with length 5 |
| `a;b=@` | **panic** — index out of range [5] with length 5 |
| `@-` | clean error (`isNeg` consumes `-`, then `eof()` fires) |
| `@1`, `?1`, `"@"` | parse normally |

So the trigger is precisely "value ends with `@`".

**Exposure.**

- *Server:* `ParseProxyRequest` runs on an unauthenticated CONNECT-UDP request,
  before `authenticateCarrierRequest`. Any peer that can reach the proxy could
  halt the serving goroutine.
- *Client:* `nextHopAddr` parses `Proxy-Status` from the proxy's response. A
  hostile proxy, or an active prober able to inject or tamper with a response
  header, could halt the user's client. Under Winn's threat model this is the
  more serious of the two: a client crash is both denial of service and a
  distinguishing signal.

`quic-go` does not link `httpsfv`, so the blast radius is these two call sites.

**Fix.** `v1.1.0` is the newest published release; there is no upstream fix to
take. `internal/masque/sfv.go` (new) adds `unmarshalItemSafely`, which recovers
any panic from the third-party parser and converts it into an ordinary error.
Both call sites now route through it. The recover is deliberately placed around
the whole parser rather than around the one known input shape, because the
defect class is "unchecked index in a hand-written scanner" and one missing
bounds check is unlikely to be the only one.

Rejections keep their existing shape: `ParseProxyRequest` still returns a
`ProxyRequestParseError` with HTTP 400, so the fix introduces no new
distinguishable response.

**Regression tests** — `internal/masque/sfv_test.go`:

| Test | Covers |
|---|---|
| `TestUnmarshalItemSafelyRecoversUpstreamPanic` | all four known panicking values |
| `TestUnmarshalItemSafelyPreservesValidParses` | wrapper is transparent on the normal path |
| `TestParseProxyRequestSurvivesMalformedCapsuleHeader` | end-to-end server path, asserts HTTP 400 |
| `TestNextHopAddrSurvivesMalformedProxyStatus` | client path, hostile `Proxy-Status` |

The crashing input is retained as a fuzz seed at the path above, so
`go test ./internal/masque/` re-runs it on every build.

**Upstream.** Worth reporting to `dunglas/httpsfv`. The fix upstream is a single
`s.eof()` guard at the top of `parseNumber`. Until a fixed release exists, the
wrapper must stay; `sfv.go` documents the removal condition.

---

### F-2 — H2 frame reader does not self-resynchronise (latent, defence-in-depth)

**Severity:** Low as it stands — not currently reachable. Recorded because the
safety depends entirely on caller discipline.

**Where:** `internal/carrier/h2.go:771` `readFrameInto`.

On an invalid length prefix the function returns an error having consumed only
the 2-byte header, leaving the stream positioned **inside** the body the peer
declared:

```go
length := int(binary.BigEndian.Uint16(header[:]))
if length == 0 || length > maxDatagram {
    return 0, errors.New("invalid H2 carrier datagram length")  // body not drained
}
```

A caller that retries on the same reader would parse its next length prefix from
an attacker-chosen offset. The brief noted the datapath lane deliberately
latches after an invalid frame; this reader does not latch *itself*, it relies
on its callers to.

**Verification — every production caller does latch.** This was checked
individually:

| Reader | Behaviour on malformed input | Safe? |
|---|---|---|
| `h2EnvelopesToUDP` (`server_envelope.go:108`) | `return err`, terminates the session | yes |
| `h3EnvelopesToUDP` (`h3_envelope.go:103`) | `return err`, terminates the session | yes |
| `envelopePacketConn.ReadFrom` (`envelope.go:116`) | returns the error up; loops only for successfully-decoded cover/probe-ack control frames | yes |
| relay carrier-to-local loop (`relay.go:241`) | `count == 0 && readErr != nil` → terminal error, returns | yes |
| `h2PacketConn.ReadFrom` (`h2.go:649`) | surfaces the error; does not close, but has no retrying consumer | yes, by caller |
| `packetConn.ReadFrom` (`common.go:44`) | oversize → `ErrDatagramTooLarge`; datagram-oriented, desync impossible | yes (and only used by tests) |

So there is no live desynchronisation. The gap is that `readFrameInto` is not
self-protecting.

**Status: reported, not patched.** `internal/carrier/h2.go` is being actively
edited by the carrier-socket lane (mtime 2026-08-03 10:45). Per the coordination
constraint this file was left alone. The proposed defence-in-depth change is to
drain the declared body before returning, so the reader resynchronises on the
next frame boundary rather than mid-body — or, more simply, to have the caller
close the stream. Either belongs to whoever owns `h2.go`.

Pinned by two new tests in `internal/carrier/framing_fuzz_test.go`, which do not
touch `h2.go`:

- `TestReadFrameIntoDoesNotConsumeBodyOnInvalidLength` — documents the exact
  current behaviour and demonstrates the consequence, so a future caller that
  retries instead of latching fails here first.
- `TestReadFrameIntoRejectsZeroAndOversizeLengths` — locks the two length checks
  that keep the 16-bit prefix from driving an allocation or an empty-frame loop.

---

### F-3 — Leads investigated and cleared

Recorded so the auditor does not re-spend time on them.

| Lead | Verdict |
|---|---|
| `internal/auditcheckpoint/checkpoint.go:1072` `mustDecodeBase64` | **Not a panic.** Despite the name it returns `nil` on error. Misleading name only. |
| `internal/privacytoken/token.go:624` `payloadWithoutSignature` | **Sound.** Its one caller, `NewCredentialSigner`, operates on the client's *own* bundle and cross-checks that the supplied seed derives the committed public key. No remote trust. |
| `internal/masque/proxy_request.go:87` `uritemplate` match on non-matching URL | **Nil-safe.** `Values.Get` handles a nil map and `Value.String()` guards on `Valid()`. |
| `internal/carrier/envelope.go` malformed datagram tears down the carrier | **Correct fail-closed.** The only envelope parser sits behind TLS (h2) or QUIC AEAD (h3); `limitPacketConn` is referenced solely from tests. An off-path attacker cannot inject, so a malformed envelope means the authenticated peer misbehaved and teardown is right. |
| `internal/carrier/h3_envelope.go:102` attacker-derived `outerSize` → `make` | **Bounded** at line 99 against `maxOuter`, and again inside `encodeEnvelope` against `AbsoluteMaxCarrierEnvelope`. |
| `internal/awg/applier.go:248` length-derived allocation from `wg show` stdout | **Out of threat-model scope.** Input is a local privileged subprocess with an absolute, validated binary path — not network input. Unbounded in principle; noted as low-priority hygiene, not a defect. |
| `internal/carrier/server_envelope.go:66` `sequence + d.window` overflows uint64 | **Real arithmetic wart, not a vulnerability.** With an attacker-chosen `sequence` near `MaxUint64` the sum wraps. It fails *closed* (the packet is dropped), and the only party that can reach it is the authenticated peer acting against its own session — a self-DoS. Memory is properly bounded: `state.seen` is pruned to `d.window` on every accept (lines 76–84) and sessions are capped at `d.max`. Deliberately **not** patched: the obvious rewrite (`state.highest > d.window && sequence <= state.highest - d.window`) is equivalent for all non-overflowing inputs, but in the overflow case it *accepts* the huge sequence and latches `highest` to it, which makes window poisoning easier rather than harder. Today's wrapped comparison drops it. Which behaviour is right depends on how the two-carrier handoff allocates sequences, which was not in scope for this review. Flagged for whoever owns the handoff design. |

---

## 3. Class-by-class results

The brief asked for five specific classes rather than generic coverage.

| Class | Result |
|---|---|
| **Unbounded allocation from attacker-supplied length** | None found on any network path. Every wire-length-driven copy uses `append([]byte(nil), b[a:c]...)` after an explicit bound check; there is no `make([]byte, n)` with unvalidated wire `n`. The four length-influenced allocations are all bounded (see F-3). |
| **Integer conversion / truncation on wire fields** | None reachable, and the reason is structural. Every decode-side conversion is `uint16 → int` — **widening** on a 64-bit target, so truncation is impossible. All 9 such sites were enumerated: `wcf3/frame.go:181`; `carrier/h2.go:776`; `carrier/envelope.go:436`; `echconfig/ech.go:274,283,301,360,372,394`. Every *narrowing* conversion (`int → uint16/uint32`, the `#nosec G115` sites) is on the **encode** side with an explicit preceding bound, each of which was checked: `wcf3/frame.go:134` (payload ≤ 1436 via `validateFrame`), `wcf3/frame.go:324` (fields ≤ 128 via `connectivity` `identifierPattern`/`sessionPattern`/`digestPattern`), `echconfig/ech.go:72,257,411`, `carrier/h2.go:797`, `carrier/envelope.go:423`. |
| **Desynchronisation after a malformed frame** | One latent gap, F-2. All six production readers enumerated and individually verified to fail closed. |
| **Nil handling on optional fields** | No nil-deref found. `uritemplate` and the optional capsule header are nil-safe; `ReplayWindow.Accept` and `DecodeWithReplay` guard nil receivers and nil context/window arguments. |
| **Panics reachable from remote input** | **One found and fixed** — F-1. No others surfaced across 4 h 55 m of cumulative per-target fuzz time. |

---

## 4. Campaign results

Every target ran with `-parallel=4`. Fuzz time per target is stated exactly;
where a target is slow, its low execution count is reported as-is rather than
dressed up.

### 4.1 Pre-existing targets — 15 minutes each

<!--PHASE1_TABLE-->

### 4.2 New targets — 10 minutes each

<!--PHASE2_TABLE-->

### 4.3 Honest notes on campaign quality

- `FuzzVerifyMLDSASignatureEncoding` and `FuzzVerifyDomainMessage` achieve very
  low execution rates because each execution performs real ML-DSA work. Their
  low exec counts are reported as measured. They exercise length and encoding
  handling, which is what matters, but they are **not** deep cryptographic
  coverage and should not be presented as such.
- `FuzzDecode` (wcf3) reached 194 M executions and found only 1 new interesting
  input in 15 minutes, i.e. its corpus had already saturated the reachable state
  space of the structural decoder. Further time on that target has low value;
  the useful frontier there is the *stateful* path, which is why
  `FuzzDecodeWithReplay` and `FuzzReplayWindowAccept` were added.
- A target that runs clean proves the absence of crashes **for the inputs it
  reached**, nothing stronger.

---

## 5. New fuzz targets added

13 new targets in 7 packages. Deliberately not 40 shallow ones — each targets a
parser that takes attacker-controlled bytes and enforces a real invariant beyond
"did not panic".

| Target | File | Why it earns its place |
|---|---|---|
| `FuzzValidateConfigList` | `internal/echconfig/config_fuzz_test.go` | Hand-rolled RFC 9849 nested length-prefix parser. Reached **pre-signature** from `gatewaymanifest.VerifyV2` → `validatePublicTLSFields` → `ValidateConfigList`, so it parses unverified manifest bytes. Asserts framing self-consistency, determinism, and base64 round trip. |
| `FuzzValidateConfig` | same | Shorter path to the public-name and extension-vector walk; asserts an accepted config always yields a valid 32-byte X25519 key. |
| `FuzzReplayWindowAccept` | `internal/wcf3/replay_fuzz_test.go` | WCF3 headers are transmitted in clear, so an on-path observer can copy a session/binding context and inject arbitrary sequences. Asserts the bookkeeping map stays within the configured window (remote memory exhaustion) and no sequence is accepted twice. |
| `FuzzDecodeWithReplay` | same | The composed production receive path: structural decode + context binding + replay consumption. Asserts identical bytes are never accepted twice. |
| `FuzzRequestClaimsFromHeaders` | `internal/carrierauth/claims_fuzz_test.go` | The full unauthenticated claim set, parsed before any ML-DSA verification. The existing `FuzzSignatureHeader` covered only one header. Asserts no CR/LF survives validation into canonicalisation. |
| `FuzzResponseClaimsFromHeaders` | same | Client-side mirror: hostile server response before signature check. |
| `FuzzParseTimestamp` | same | Unauthenticated input feeding time arithmetic. |
| `FuzzParseProxyRequest` | `internal/masque/proxy_request_fuzz_test.go` | **Found F-1.** First code a proxy runs on a new peer. Asserts every rejection carries a valid HTTP status and accepted dial targets contain no whitespace or CRLF. |
| `FuzzDecodeManifestV2` | `internal/gatewaymanifest/manifest_v2_fuzz_test.go` | Remote manifest JSON, validated before signature check. Asserts validate → encode → decode → validate round trip and digest stability, which is where signature-canonicalisation bugs live. |
| `FuzzDecodeSignature` | `internal/pqauth/decode_fuzz_test.go` | Guards every signed message on the wire. |
| `FuzzVerifierSetDocument` | same | Trust material; builds real ML-DSA verifiers from attacker-chosen base64. |
| `FuzzVerifyDomainMessage` | same | Length handling ahead of the constant-time verify. |
| `FuzzReadFrameStream` | `internal/carrier/framing_fuzz_test.go` | Reads a **sequence** of frames rather than one, which is what exposes resynchronisation. Asserts forward progress on every path — a rejection that consumed nothing would let a retrying caller spin forever. |

---

## 6. Dependency advisory status

`govulncheck` (`golang.org/x/vuln`, installed for this review) run over `./...`:

```
=== Symbol Results ===

No vulnerabilities found.

Your code is affected by 0 vulnerabilities.
This scan also found 0 vulnerabilities in packages you import and 1
vulnerability in modules you require, but your code doesn't appear to call these
vulnerabilities.
```

The one module-level vulnerability is in a required module whose vulnerable
symbols are not reachable from this code.

Versions handling hostile input:

| Module | Version | Status |
|---|---|---|
| `github.com/quic-go/quic-go` | v0.60.0 | no applicable advisory |
| `github.com/quic-go/qpack` | v0.6.0 | no applicable advisory |
| `golang.org/x/crypto` | v0.53.0 | no applicable advisory |
| `golang.org/x/net` | v0.56.0 | no applicable advisory |
| `golang.org/x/sys` | v0.46.0 | no applicable advisory |
| `github.com/cloudflare/circl` | v1.6.3 | no applicable advisory |
| `github.com/dunglas/httpsfv` | v1.1.0 | **no advisory, but see F-1** — remote panic found by this review; v1.1.0 is the newest release, so there is nothing to upgrade to |
| `github.com/yosida95/uritemplate/v3` | v3.0.2 | no applicable advisory; verified nil-safe |
| `github.com/jackc/pgx/v5` | v5.10.0 | no applicable advisory; not on a network-input path |

**The important lesson for the audit:** `govulncheck` was clean while a
genuine unauthenticated remote panic sat one call away in `httpsfv`. Advisory
scanning and fuzzing are not substitutes for each other.

---

## 7. Remaining unfuzzed surface, ranked by risk

Ranked by how directly attacker-controlled the input is and how much
hand-written parsing sits behind it.

| # | Surface | Location | Risk | Why it is not yet fuzzed |
|---|---|---|---|---|
| 1 | MASQUE capsule / datagram read path | `internal/masque/conn.go:86` `ReadFrom`, `skipCapsules` | **High** — `quicvarint.Parse` on remote datagrams, silent truncation into caller buffer, live capsule stream | Needs a mock `http3.Stream`; not cheap. Highest-value next target. |
| 2 | Bootstrap controller HTTP server | `internal/bootstrap/server.go:66` `ServeHTTP` | **High** — remote JSON body, `mime.ParseMediaType` on attacker `Content-Type` | Needs HTTP plumbing to reach the decoder; a byte-level entry point would make this cheap. |
| 3 | Bootstrap client response parsing | `internal/bootstrap/client.go:189,199` | **High** — controller response JSON is parsed **before** ML-DSA verification; hostile-server path against the client | Same plumbing cost. |
| 4 | DNS response parsing on the protected path | `internal/directawg/linux_protected.go:266` `dnsmessage.Message.Unpack` | **Medium** — genuine network input from a resolver, though `x/net/dns/dnsmessage` is well-audited and the buffer is a fixed 4096 with strict post-checks | Linux-oriented probe path; needs a socket harness. |
| 5 | Privacy token full verify path | `internal/privacytoken/token.go:256` `Verify` | **Medium** — post-signature JSON decode, then `pqauth.NewVerifier` on token-embedded key bytes | Needs a pre-generated RSA issuer key to be fast; `DecodeTokenHeader` (fuzzed) covers the pre-auth half. |
| 6 | Issuance authorization headers | `internal/privacytoken/issuance.go:87` `Verify` | **Medium** — issuer server parses attacker headers, hex digest decode | Server-side only; lower reach than the carrier path. |
| 7 | Session deduplicator | `internal/carrier/server_envelope.go:44` `Accept` | **Low-Medium** — peer-chosen sequence and session key; memory verified bounded by hand (see F-3), but the window arithmetic overflows and the eviction path is stateful | Structurally identical to `ReplayWindow.Accept`, so `FuzzReplayWindowAccept` is a ready-made template. Best value-for-effort follow-on. |
| 8 | Transparency log / audit chain readers | `internal/transparency/log.go:175`, `internal/auditcheckpoint/checkpoint.go:637` | **Low-Medium** — signed documents, scanner-bounded, but large hand-written verify logic | File-sourced; attacker needs the distribution path. |
| 9 | `internal/realcycle`, `internal/realtopology` document parsers | many | **Low** — already have two JSON-shape targets; canonical round-trip checks are strong | Partially covered. |
| 10 | `internal/costledger`, `internal/phase1anchor` decoders | `cost.go:397`, `anchor.go:147` | **Low** — operator-supplied, size-capped; `phase1anchor.DecodeRequest` reads stdin | Not network-reachable. |

Items 1–3 are where I would spend the next block of effort.

---

## 8. Corpus

The generated corpus is committed under each package's
`testdata/fuzz/<Target>/` so an auditor can rerun it without re-deriving
coverage:

```
go test ./internal/... -run 'Fuzz'          # replays the whole committed corpus
go test ./internal/masque/ -run FuzzParseProxyRequest   # replays the F-1 crasher
```

To resume fuzzing rather than replay:

```
go test ./internal/echconfig/ -fuzz FuzzValidateConfigList -fuzztime=15m -parallel=4
```

Entries are Go's coverage-deduplicated "interesting" inputs, not raw random
data, so the corpus is a genuine coverage artefact.

---

## 9. Baselines

All verified after every change in this review:

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass, no diagnostics |
| `go test ./... -count=1` | pass — 66 packages ok, 0 failures |
| `gofmt -l` on all touched files | clean |

---

## 10. Coordination notes

Two other lanes were editing `winn_protocol_experimental/**` concurrently: a
handshake lane and a carrier-socket lane converting h2/h3/masque to
caller-supplied sockets.

**Files deliberately left alone** (mtime 2026-08-03, owned by the other lanes):
`datapath/**`, `cdatapath/`, `cshared/`, `clientbinding/`, `cmd/winn-datapath/`,
`cmd/winn-clientinfo/`, and in `internal/carrier`: `h2.go`, `h3.go`,
`h3_migration.go`, `supplied_socket.go`, `supplied_socket_test.go`.

This is why F-2 is reported rather than patched — the fix belongs in `h2.go`.

**Files added** (no conflict risk):

```
internal/echconfig/config_fuzz_test.go
internal/wcf3/replay_fuzz_test.go
internal/carrierauth/claims_fuzz_test.go
internal/masque/proxy_request_fuzz_test.go
internal/masque/sfv.go
internal/masque/sfv_test.go
internal/gatewaymanifest/manifest_v2_fuzz_test.go
internal/pqauth/decode_fuzz_test.go
internal/carrier/framing_fuzz_test.go
docs/reviews/fuzz-hardening-20260803/README.md
```

**Files modified — please reconcile if the carrier-socket lane also touched
`internal/masque`.** Both changes are one line each plus an import removal:

| File | Change |
|---|---|
| `internal/masque/proxy_request.go` | `httpsfv.UnmarshalItem(...)` → `unmarshalItemSafely(...)`; dropped the now-unused `httpsfv` import |
| `internal/masque/client.go` | same substitution in `nextHopAddr`; dropped the now-unused `httpsfv` import |

`internal/masque` had not been modified today when this work started
(`proxy_request.go` and `client.go` both predate 2026-08-02), and both files are
request/response parsing rather than socket plumbing, so collision risk is low —
but the carrier-socket lane's brief does name masque, so it is flagged here.

No sealed evidence, append-only log, or `docs/handoff/*.md` file was touched. No
key material appears in any added file.
