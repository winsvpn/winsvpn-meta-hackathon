# Single Packet Authorization for Winn Protocol v3 — Design

Owner: admin@winsvpn.org · 2026-08-04 · Status: **implemented, unit- and
integration-tested, wired opt-in into `cmd/winn-carrier-server` and
`cmd/winn-carrier-client`. Not yet run against a real gateway.**

This is an **alternative, opt-in connection-initiation mechanism**. It does
not replace the existing cover-profile design (`internal/coverlisten`,
`internal/decoy`, mandatory ECH) and is off by default. See §7 for why it is
additive rather than a replacement.

---

## 1. Survey: does a knock/SPA/pre-auth mechanism already exist?

No. Verified by direct search before writing any code:

```
grep -rniE "knock" --include="*.go" --include="*.md" .          -> 0 hits
grep -rniE "single[- ]packet|\bspa\b|fwknop" --include="*.go" --include="*.md" .
                                                                  -> 1 hit, unrelated
                                                                     (WINN_PROTOCOL_V3_CONTINUATION_LOG.md:2384,
                                                                     "a single packet with a 2s timeout" - a
                                                                     description of an unrelated integration
                                                                     test, not a mechanism)
```

`pre-auth` **does** appear, but names a different thing: `internal/connlimit`
and the `-max-preauth-connections`/`-max-preauth-connections-per-ip` flags on
`cmd/winn-server`, `cmd/winn-token-issuer`, and `cmd/winn-carrier-server`
bound the number of **already-accepted TCP connections** before their TLS
handshake authenticates. The port is still open, still completes a real TLS
handshake with anyone, and still returns a real (cover) HTTP response to
every prober. That is the opposite property from what this task asked for.

What the tree has instead is `internal/coverlisten` + `internal/decoy` +
mandatory ECH: every listener answers every probe convincingly (looks like
an ordinary HTTPS site) rather than answering not at all. That is a
deliberate, load-bearing design already hardened through an adversarial
review (`docs/reviews/fugu-ultra-adversarial-20260803/FINDINGS.md`) — see §7
for why this design adds to it instead of contradicting it.

**Conclusion: no knock/SPA/port-visibility mechanism existed anywhere in
`winn_protocol_experimental/` before this change.**

## 2. Requirements (from the task)

1. Replay-resistant: a captured packet must not re-open the port.
2. Must not add a distinguishable fingerprint. A fixed-size UDP packet to a
   fixed port is itself a fingerprint — must be addressed explicitly, not
   waved away.
3. Must fail closed.
4. Must work behind CGNAT with a changing client source address.
5. Crypto must reuse what the tree already has (hybrid PQ via `crypto/tls`
   named groups, ML-DSA-65/87 via `cloudflare/circl`, SHA-256). No new
   primitives or dependencies without saying so loudly.

## 3. Options considered

### A. Classic fwknop-style SPA: one authenticated UDP packet, sent
   independently of the real connection attempt, to the same port the
   carrier already listens on.

### B. An encrypted knock embedded in the existing first handshake datagram
   (e.g. prepended to the QUIC Initial packet, the way AmneziaWG prepends
   S1 padding before a handshake initiation — see
   `docs/handoff §10.6`/`datapath.AWGHeaderTypes`).

### C. Classic multi-packet TCP/UDP port-knock sequences (knock ports
   N, N+1, N+2 in order).

### Comparison

| | A. Single-packet SPA (separate datagram) | B. Embedded in first datagram | C. Multi-packet port-knock sequence |
|---|---|---|---|
| Round trips added | +1 UDP RTT before the real attempt | 0 (rides with the real Initial) | +N (one per knock port) |
| Covers the H2 (TCP) carrier too | Yes — one UDP knock authorizes both listeners (§5) | **No.** TCP's first flight is a bare SYN; no payload without TCP Fast Open, which is a new mechanism, platform-inconsistent, and its own fingerprint | Yes, but see below |
| Compatible with this tree's crypto without forking anything | Yes (§4) | Would need either a custom TLS/QUIC extension (Go's `crypto/tls` does not expose arbitrary ClientHello extensions to the application) or raw byte-prepending outside the QUIC packet — the latter degenerates into option A anyway, just coupled to one carrier | Yes, trivially (payloads are simple) |
| Consistent with an existing project decision | — | Contradicts the recorded uTLS rejection: "it would break the audit claim that all PQ key exchange is standard-library-only" (docs/handoff §10.7). Touching ClientHello/Initial framing to smuggle a knock runs into the same objection. | — |
| Detectability of the mechanism itself | A knock is one datagram, sized and shaped to match the port's existing QUIC-Initial population (§4.3) | Same population, but now two different "first datagrams" exist on the wire depending on whether SPA fired — a new distinguishable state | A *sequence* of connection attempts to normally-closed ports, in a fixed order, from one source, is a well-known, actively-fingerprinted pattern — GFW-class censors already look for it. This is a worse fingerprint than a single packet, not a better one. |
| Replay handling | Nonce + nearby-time-bucket HMAC, independent of any live connection state (§4.2) | Same crypto, but now entangled with QUIC's own anti-replay/Initial handling | Sequence itself is replayable unless every packet in it is authenticated, at which point it is strictly worse than A with more packets |
| Maturity / prior art | fwknop, 20+ years of production use and cryptanalysis | Not aware of a shipping precedent doing this over QUIC specifically | Original 1990s port knocking; long superseded by SPA in the circumvention/hardening literature for exactly the replay and fingerprint reasons above |

### Recommendation: **A — classic fwknop-style single-packet SPA**, sent as
its own UDP datagram to the same port (`udp/<addr>`) the H3 carrier already
listens on, gating **both** the H2 and H3 listeners from one shared
authorization state.

Reasoning, in order of weight:

1. **B cannot cover TCP at all**, and this deployment races two carriers
   (H2 over TCP, H3/masque over UDP) for the same connection. Needing two
   different initiation mechanisms — one embedded, one separate — for one
   feature is more code, more fingerprint surface, and more chances for the
   two to drift apart, for no benefit A does not already provide.
2. **B's stronger form (byte-prepend to the same datagram) reduces to A
   anyway**, just coupled to the QUIC socket specifically instead of
   independent of carrier choice. Coupling it removes exactly the property
   (one knock authorizes whichever carrier wins the race) that makes A
   simple.
3. **C is a known-inferior, actively-fingerprinted pattern.** It is not a
   real contender; SPA exists specifically because sequential port-knocking
   was found wanting. Included here only because the task asked for an
   explicit comparison.
4. **A's one added round trip is cheap against this project's own measured
   numbers.** The Phase 1 acceptance evidence
   (`docs/handoff §2`, `/opt/winn-lab/measurements/acceptance_10k.jsonl`)
   shows p50=62.93 ms, p95=81.22 ms, p99=84.88 ms for 10,000 warm connects
   against the 3-second connect-or-fail contract. One extra local-network
   UDP RTT before that sequence is not the bottleneck.
5. **A is the only option with two decades of adversarial scrutiny already
   behind the underlying idea.** This implementation does not reuse
   fwknop's code (Go, different crypto stack, different transport model)
   but it reuses the *shape* of the mechanism, which is the part that has
   actually been attacked and hardened in the field.

## 4. Design of A: what makes it fit *this* tree specifically

### 4.1 Wire format

A knock is exactly `PacketSize` bytes:

```
[0:16)  nonce    - random, also the replay-tracking key
[16:48) tag      - HMAC-SHA256, 32 bytes
[48:..) padding  - random, uninterpreted
```

`PacketSize` is not a package constant. The integration in
`cmd/winn-carrier-server` sets it to
`carrier.H3InitialPacketSize(maxDatagram + carrier.CarrierEnvelopeOverhead)`
— **the exact same formula that already sizes this deployment's QUIC
Initial packets** (`cmd/winn-carrier-server/main.go`, `initialPacketSize`).
This is the direct answer to requirement 2: a knock is not a new size class
on this port, it is the same size class the only other legitimate
pre-handshake datagram already uses. `cmd/winn-carrier-client` computes the
identical value from the same formula rather than a hardcoded default, so
the two cannot silently drift apart.

There is deliberately **no version byte, timestamp, or key ID on the
wire** — every field that is not the nonce or the tag is authenticated but
never transmitted, recomputed by the verifier instead:

* The protocol version is a single supported constant, checked implicitly
  by which key/bucket combinations the verifier tries.
* The freshness window is a small number of "nearby time buckets" the
  verifier tries against its own clock (the same trick TOTP uses to avoid
  sending a timestamp in the clear), not a claimed timestamp from the
  packet. A cleartext 8-byte Unix timestamp would itself be a passive
  distinguisher — it only ever takes values within seconds of true
  wall-clock time, which is a different, learnable statistical shape from
  both random background noise and an encrypted QUIC Initial.

The result is that a knock's on-wire bytes — nonce, tag, padding — are, to a
passive observer, three concatenated blocks of high-entropy data of the
same total size as the port's other pre-handshake traffic. There is no
plaintext structure left to fingerprint beyond size, and size is matched by
construction.

### 4.2 Replay resistance

The nonce is the replay key. `Gate` (the server-side state machine, in
`internal/knock/gate.go`) keeps a bounded, TTL'd map of nonces already
consumed, sized to the freshness window (`2×MaxSkew + BucketWindow`). A
resent, captured knock fails the replay check even though it would still
cryptographically verify — proven experimentally, not just argued, by
`TestGateUDPReplayedKnockDoesNotReopenPort` in
`internal/knock/gate_test.go`, which authorizes a real source over a real
UDP socket, lets the authorization window lapse, resends the identical
captured bytes, and asserts the port stays closed to it.

### 4.3 Why HMAC-SHA256, not ML-DSA — said loudly, per the brief

This is the one place this design **does not** reuse the tree's existing
asymmetric primitive, and the reason is arithmetic, verified by direct
execution against the pinned `cloudflare/circl v1.6.3`
(`internal/knock/knock_test.go`,
`TestSignatureSizesConfirmMLDSAIsUnsuitableForOneUDPDatagram`):

```
ML-DSA-65 SignatureSize = 3309 bytes
ML-DSA-87 SignatureSize = 4627 bytes
carrier.H3InitialPacketSize ceiling = 1452 bytes
```

Either ML-DSA signature is already larger than the largest UDP datagram
this port's own sizing rules ever produce, **before** a nonce, header, or
padding are added. Putting an ML-DSA-signed knock in one UDP datagram
would require IP fragmentation, and fragmented UDP is itself a long-standing
censor heuristic (fragmentation is a classic evasion tool, so networks that
already scrutinize or drop it would turn the knock into a *worse*
fingerprint than not having SPA at all). A verification-cost argument
points the same direction independently: this port is exactly the surface
exposed to anonymous internet scanning, and HMAC verification is orders of
magnitude cheaper than an asymmetric signature check, which matters because
it bounds the CPU a flood of forged knocks can extract before the length
filter and rate limiter even engage (see §4.4).

**What this loudly is:** SHA-256 (via `crypto/hmac` + `crypto/sha256`,
Go stdlib, zero new module dependency — `internal/pqauth` already imports
`crypto/sha256` directly for other purposes). **What this loudly is not:**
free. The SPA key is new key material with no analogue in the existing
per-device ML-DSA registry — a deployment- or gateway-scoped shared secret,
structurally the same trust model as a shared fwknop key or an unlisted Tor
bridge line, not a per-device identity. It does not replace, weaken, or sit
in the same trust tier as any device's ML-DSA identity: SPA only decides
whether a source address gets *any* response from the listeners; every
authentication and revocation property the tunnel itself relies on
(`internal/carrierauth`, `internal/pqauth`, mTLS, `internal/revocation`) is
completely unchanged and still runs, unweakened, on whatever gets through.
Provisioning and rotating this new secret should go through the same
owner-controlled, out-of-band channel already used for the trust-root
fingerprint and gateway manifest signing keys
(`docs/handoff §10.4` item 1) — this was not built, since it is
process/procurement, not code, exactly the same shape as the note already on
record for alternative-routing domain distribution (`docs/handoff §10.7c`).

### 4.4 Fail-closed and DoS posture

* **Length check before any crypto.** A datagram whose length does not
  exactly match `PacketSize` is dropped before HMAC is ever computed — this
  is what keeps `considerKnock` cheap against the internet background noise
  that dominates traffic to any public UDP port.
* **Per-source rate limiting before crypto**, reusing
  `internal/ratelimit.BucketLimiter` unchanged — the same type
  `cmd/winn-carrier-server` already uses for post-auth establishment
  limiting, now applied one layer earlier, pre-auth.
* **Bounded memory, fail closed under pressure.** Both the authorized-address
  set and the replay cache are capacity-bounded maps that prune expired
  entries opportunistically and **refuse new grants once full** rather than
  evicting a live entry or growing without bound
  (`TestGrantFailsClosedWhenAuthorizedSetIsFull`,
  `TestMarkNonceUsedFailsClosedWhenReplayCacheIsFull`).
* **Never a distinguishing response.** Every rejection path — wrong length,
  rate-limited, bad signature, replay — is silent. Nothing on the wire tells
  an prober which of those four happened, only that nothing happened.
* **TCP's honest limit, stated rather than hidden.** A raw SYN scan still
  gets a SYN/ACK: the kernel completes the three-way handshake before this
  process's `Accept()` runs, and no portable, dependency-free, application-layer
  mechanism changes that. What SPA removes is everything *after* the SYN/ACK
  for an unauthorized source: the connection is accepted and immediately
  closed with zero bytes — no TLS handshake, no cover certificate reaches
  it. A true SYN-level firewall block (the way fwknop's own default operates,
  by rewriting `iptables`/`nftables` rules) was considered and rejected for
  this deliverable: it is Linux-only in this tree already
  (`internal/directawg`'s own `!linux` build tags), needs root/`CAP_NET_ADMIN`
  the carrier process does not otherwise require, and is a materially larger
  and riskier change than an application-level gate. It is a reasonable v2
  for Linux fleet nodes specifically and is not implemented here.

## 5. CGNAT and the sliding authorization window

Authorization is keyed by **source IP only, never by port or full 4-tuple**,
and the "port is open" state (`Gate.authorized`) **slides forward** on every
forwarded datagram or accepted connection rather than expiring on a fixed
timer:

* A NAT that rebinds the source port between the knock and the real
  connection attempt (common under CGNAT) still authorizes correctly, since
  the port is never part of the key.
  `TestGateUDPAuthorizationScopedByIPNotPort` proves this against two real,
  independently-bound loopback sockets.
* A live session's own QUIC keepalives
  (`KeepAlivePeriod: 15s`, well under `MaxIdleTimeout: 45s` in
  `cmd/winn-carrier-server`) continuously refresh the window, so `Grace`
  (default 90s, `internal/knock/gate.go`, deliberately 2× this deployment's
  `MaxIdleTimeout`) never lapses under an ordinarily-behaving connection.
  `TestGateUDPSlidingWindowKeepsActiveSessionAuthorized` drives this with a
  controllable fake clock against real sockets.
* **What this does not solve, stated as a limitation, not glossed over:**
  a client whose public IP changes entirely mid-session (a real event for
  mobile users — see `internal/mobility`) has its migration probe from the
  new address dropped as an unrecognized knock attempt, because the new
  address was never authorized. It must knock again from the new address.
  The natural v2 — recognizing an already-established QUIC connection ID
  from a new source address, independent of IP-authorization state — needs
  `internal/mobility`'s own connection-ID handling and was deliberately not
  built here; seeSection Gate's doc comment
  (`internal/knock/gate.go`) for exactly where this would attach.
* **What sharing a CGNAT IP costs, stated precisely:** everyone behind the
  same egress IP as a legitimate user gets that IP's authorization window
  too — they can reach the (still cover-profile-protected, still
  mTLS/ML-DSA-gated) listeners during that window, but not the tunnel
  itself. This is the same tradeoff every IP-scoped SPA or unlisted-bridge
  design makes; it is not specific to this implementation, and it does not
  weaken anything downstream of the gate.

## 6. What was implemented, and what running it means

**Fully implemented and unit/integration-tested, with real sockets, race
detector clean:** `winn_protocol_experimental/internal/knock/` —
`knock.go` (wire format, `Build`/`Verify`), `gate.go` (`Gate`,
`WrapPacketConn`, `WrapListener`), `client.go` (`Send`, `SendVia`),
`keys.go` (`LoadKeysFromFile`). 44 tests across `knock_test.go`,
`gate_test.go`, and `keys_test.go`, 93.9% statement coverage, 100% on every
fail-closed/replay/rate-limit path. Executed:

```
go test -race -count=3 ./internal/knock/...   -> ok, 3/3, no races
go test -race -cover ./internal/knock/...      -> ok, 93.9% of statements
```

**Wired, opt-in, off by default, into the real binaries — compiles, vets,
and its flag/validation/key-loading logic is proven by running the actual
built executables (not merely compiling them):**

* `cmd/winn-carrier-server`: new `-spa-required` / `-spa-keys` flags. When
  set, both the H2 TCP listener and the H3 UDP socket are wrapped by one
  shared `knock.Gate` before being handed to `http.Server.ServeTLS` /
  `http3.Server.Serve` respectively — one knock authorizes whichever
  carrier a client's own racing logic reaches first.
* `cmd/winn-carrier-client`: new `-spa-required` / `-spa-key-file` flags.
  When set, the client sends one knock to every candidate gateway node
  (parsed from the signed manifest or lab-mode flags) before calling
  `manager.Connect` — additive, does not touch the existing dialer/candidate
  construction at all.
* Verified by executing the built binaries directly, e.g.:
  `winn-carrier-server -spa-required` (no `-spa-keys`) exits 1 with
  `"spa-keys is required when -spa-required is set"`; supplying a
  two-key file to the client's single-key `-spa-key-file` exits 1 with
  `"spa-key-file must contain exactly one key for a client, found 2"`; a
  syntactically valid key file is accepted and execution proceeds to the
  next (unrelated) validation stage, both confirmed by actually running the
  compiled executables, not by reading the code.

**Not executed, and not claimed as executed:** a live `winn-carrier-server`
with `-spa-required` gating a real deployment, dialed by a real
`winn-carrier-client` with `-spa-required`, against a real AWG backend.
Reaching that requires the lab's real certificates, ECH key set, signed
gateway manifest, and device identity material (`AICORE`,
`/opt/winn-lab/...`), none of which exist in this sandbox. Everything up to
that boundary — the SPA primitives themselves, and the flag/validation/
key-loading plumbing in both binaries — is proven by real execution as
described above; the live-gateway run is the next lane's owner-authorized
step, the same "compiles only" / "unit-proven only, not yet proven on real
hardware" boundary already used throughout `docs/handoff` for other lanes'
work.

## 7. Why additive, not a replacement

The existing cover-profile design's whole premise is "look like an ordinary
HTTPS site to anyone who asks" — camouflage by blending in, hardened through
an adversarial review that specifically praised the cryptography and flagged
the *wire behaviour* as the weak point
(`docs/reviews/fugu-ultra-adversarial-20260803/FINDINGS.md`). SPA's premise
is the opposite: "look like nothing is there at all" — camouflage by
appearing dead. These are legitimate, different threat-model responses
(compare: public, discoverable bridges designed to blend in, versus private,
unlisted bridges designed to be hard to find at all — both patterns already
exist in the circumvention-tool space for exactly this reason), not
competing implementations of the same idea, and picking one does not
invalidate months of adversarial work on the other. Making SPA strictly
opt-in and off by default means:

* Every already-reviewed default-path property (cover certificate, decoy
  origin, ALPN widening, ClientHello mimicry) is untouched and unregressed.
* An operator serving a broadly-published, "blend in" bridge keeps today's
  behaviour exactly as reviewed.
* An operator distributing an unlisted bridge address only to specific
  at-risk users — where "unreachable by anyone without the key" is worth
  more than "looks like a boring website to everyone" — gets a real,
  tested alternative.

## 8. Next steps for whoever picks this up

1. Run a real `-spa-required` session between a lab `winn-carrier-server`
   and `winn-carrier-client` on real infrastructure (AICORE / the fleet
   nodes) and capture evidence the way the Phase 1 acceptance runs did.
2. Decide on and build the out-of-band SPA key provisioning/rotation flow
   (§4.3) — process, not code, and owner-only per the existing pattern for
   the trust-root fingerprint.
3. Consider the v2 connection-migration extension (§5) if SPA-gated
   deployments need to support client roaming, coordinating with whoever
   owns `internal/mobility`.
4. Consider a Linux-only, opt-in nftables-backed SYN-level block (§4.4) if
   "a raw SYN scan sees nothing" becomes a hard requirement rather than
   "a raw SYN scan learns nothing useful."
5. `cmd/winn-server` and `cmd/winn-token-issuer` do not have this wired in.
   They are structurally similar (also TCP listeners behind
   `internal/coverlisten`) and are reasonable candidates for the same
   `internal/knock.Gate` if the owner wants SPA on the control plane too —
   not done here to keep this change scoped to the connection-initiation
   surface the task named (`internal/carrier` + `cmd/winn-carrier-*`).
