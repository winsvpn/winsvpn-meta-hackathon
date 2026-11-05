# Winn Protocol v3

**Winn Protocol v3 (Winn v3)** is a standalone censorship-resistance tunnel
protocol: its own handshake, its own key schedule, its own transport
cryptography, and its own datapath. It is built by [Win's VPN
Inc.](https://www.winsvpn.org/) for users who need a connection that survives
hostile networks, and it is released here under the GNU Affero General Public
License, version 3 (see [License](#license)).

This is the reference implementation in Go. It consists of the pure
cryptographic core (`winn3/core`), a frame-level session driver
(`winn3/session`), the inner-IP layer that turns an established session into a
tunnel (`winn3/tun`), a server-side dispatcher for many clients (`winn3/gateway`),
and the transport carriers that move sealed messages between endpoints
(`winn3/carrier`).

Everything below is scoped to what the code actually does. Where Winn v3 is
weak, the section is titled as such and states the limitation plainly. Honest
scope is a safety property in a censorship environment: a tool that overstates
what it hides endangers the people who rely on it.

---

## Status

Winn v3's cryptographic core and datapath are complete and are exercised by the
test suite, the known-answer test vectors (`winn3/core/testdata/winn3_kat_v1.json`),
and an impairment rig (`winn3/netlab`) that reorders, drops, delays and flips
bits on real sealed messages. This is a **production candidate, not an
independently audited cryptographic product.**

Platform integration against the Win's VPN application is separate from this
repository and, as of 2026-08-11, no signed application release artifact
carries Winn v3 on any of the five platforms. The honest per-platform picture:

| Platform | Reference datapath state (2026-08-11) |
|---|---|
| Android | v3 bytes carried through a real kernel `tun` interface (debug builds); release-signing path still to land |
| macOS | build carries v3; host carriage under the current routing posture is being re-measured |
| iOS | v3 is signed and installed on the owner's device; carriage blocked on control-plane configuration delivery |
| Linux | first binary built; ~4 MB carried via socketpair + reflector on loopback, not yet through a kernel `tun` |
| Windows | cross-compiles clean; never staged, never run |

Do not read this table as "shipped". Read it as "the protocol core exists and is
tested; the platform seams are in progress."

---

## Cryptographic suite

All primitives are implemented by the Go standard library, with one exception
noted below. The suite is fixed and never negotiated:

- **Transcript hash:** SHA-256 (`crypto/sha256`)
- **Key derivation:** HKDF-SHA-256 (`crypto/hkdf`)
- **Admission MAC:** truncated HMAC-SHA-256 (`crypto/hmac`)
- **Classical DH:** X25519 (`crypto/ecdh`)
- **Post-quantum KEM:** ML-KEM-768, FIPS 203 (`crypto/mlkem`)
- **AEAD:** ChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305` — the one
  dependency outside stdlib; ChaCha20-Poly1305 is not yet in the standard
  library, and ChaCha20 is constant-time on every target without requiring AES
  hardware)

**There is deliberately no ciphersuite negotiation on the datapath.** The suite
identifier and the version label `winn/3` never appear on the wire; they are
inputs to the transcript hash, so two endpoints configured differently simply
fail to decrypt rather than negotiating. A negotiable field would be both a
fingerprint and a downgrade surface. See `winn3/core/params.go`.

Confidentiality is **post-quantum**: an ephemeral ML-KEM-768 exchange is mixed
into the session in-band as an ordinary ratchet *after* the handshake. It is
not carried in the handshake itself, because the first packet must stay under
the 1280-byte IPv6 minimum MTU and a fragmented first packet is itself a
distinctive fingerprint. Authentication rests on the classical X25519 handshake.
That asymmetry is deliberate and is stated in the limitations section below.

## What an observer sees on the wire

There are exactly two message classes, and there is no third — no cookie
message, no version message, no error message, and no close that can be told
from data:

```
Handshake:  AdmissionTag || whitened( ephemeral || sealed-static || sealed-payload )
Transport:  DemuxToken   || AEAD( frames || padding )
```

A **transport** message is unconditionally uniform-random to any observer who
is not a participant in that session: the demux token is the output of a PRF
and everything after it is AEAD output. There is no counter on the wire, no
session index, no type byte, no length field and no version — the counter is
implicit in the demux token, which the receiver precomputes in a forward
window and looks up.

A **handshake** message is uniform-random only to an observer who does not hold
that gateway's admission key. The admission layer is a *cost boundary*, not a
security boundary: its job is to move fleet identification from "byte-pattern
match at line rate" to "hold a per-gateway secret". It contributes nothing to
integrity, authentication or key agreement, and the design treats that as an
invariant. The response tag is keyed differently from the initiation tag, so
even a party holding the admission key cannot pair a response with the
initiation that produced it without the gateway's static private key.

A Winn v3 gateway **never answers an unauthenticated datagram.** There is no
cookie reply and no error packet, because an answer to an unauthenticated
packet is a probe oracle by construction. The handshake freshness bucket is an
authenticated input to the tag and is never transmitted — an explicit timestamp
would only ever take values near wall-clock time, which is a learnable
statistical shape.

## Fail-closed behaviour

This section describes what Winn v3 *does* guarantee at runtime. These are
local, in-process properties of a *running* tunnel process.

- **One carrying state.** Inner IP packets move only while the session is in
  the single `carrying` state, and only through a gate that is written as a
  whitelist of exactly one value. Not-yet-handshaken, post-quantum-ratchet
  pending, mid-rekey, closing and torn-down all mean "carry nothing", and
  nothing is written to the host in any of them (`winn3/tun/gate.go`).
- **Airtight teardown.** The gate is a drain barrier: setting it to the closed
  state blocks until every in-flight packet has been released, so when it
  returns there is no packet still on its way to the session or to the device.
- **Replay protection is exact.** A consumed demux token is erased, so a
  replayed packet finds no entry in the window. There is no sliding bitmap to
  get wrong.
- **Reordering tolerance is deliberate and bounded.** The receiver precomputes
  a forward window of expected tokens, which is simultaneously the reordering
  tolerance and the replay filter (default 1024, operator-bounded).
- **Epoch exposure is bounded.** Sessions re-key in-band on message counts,
  byte counts, or a jittered timer; each epoch's key compromise exposes a
  bounded slice of traffic rather than the whole session.

These are local, in-process properties of a *running* tunnel. They are not an
always-armed network block, and they are not a kill switch — see the next
section.

## What Winn v3 is not (limitations, stated plainly)

### Traffic-analysis resistance

Winn v3's padding and length shaping **defeat fixed-size matching and
constant-overhead arithmetic only.** Quoting the code in
`winn3/core/params.go`:

> Uniform-random padding is NOT offered, because it is itself a signature: real
> traffic is strongly bimodal (full-MTU bulk and small interactive), not
> uniform. None of these defeat a determined traffic-analysis adversary; they
> defeat fixed-size matching and constant-overhead arithmetic. Claiming more
> than that would be dishonest.

In plain terms: Winn v3 shapes message lengths so that it does not present a
fixed, fingerprintable set of packet sizes, and it avoids constant-overhead
arithmetic that would let an observer recover lengths. It does **not** resist a
determined adversary correlating flow volumes and timing, and nothing in this
repository claims otherwise. "Invisible", "undetectable", and "defeats DPI" are
not claims this project makes.

### Traffic in the clear on Apple platforms

On **macOS and iOS**, traffic sent **before the tunnel has been established,
during teardown of a tunnel, and after the tunnel provider has crashed or been
killed still egresses through the device's normal, unprotected network path.**
NetworkExtension offers a third-party packet-tunnel client no API that keeps
blocking after the tunnel is down; the tunnel's settings are the protection,
and the system reclaims them on teardown, on failure, and on crash. Nothing in
Winn v3 changes that.

The same is true on every platform while the tunnel is not carrying: Winn v3's
own fail-closed properties are in-process and disappear when the process does.
Keeping a device offline once the tunnel is down is not something Winn v3 does;
on any platform it would require a separate, platform-specific mechanism outside
this protocol core. Do not assume one exists wherever you deploy this.

### No kill switch

Winn v3 provides **no kill switch**. There is no mechanism in this codebase —
remote, local, or platform — that keeps a device offline whenever the tunnel is
not carrying. Routing posture such as route-precedence hardening applies only
while a tunnel is up and is not a substitute. Do not treat any part of this
project as one, and do not describe it as one.

### Authentication is not post-quantum

Forging a peer's identity requires breaking X25519, which needs a
contemporaneous quantum computer — but *harvest-now-decrypt-later* attacks
compromise confidentiality today, which is why the ML-KEM exchange exists.
Gateway identity does reach the client inside an ML-DSA-65-signed descriptor,
so that leg is post-quantum authenticated out of band. **Client authentication
has no equivalent quantum mitigation.** That is a known weakness, recorded in
the design rather than papered over.

### The admission layer is scoped obfuscation, not secrecy

An adversary who holds a gateway's admission key can recognise that gateway's
handshake initiations (and, with the static private key, pair them with their
responses). The layer buys *cost* and *unlinkability against a keyless
observer*; it does not hide the existence of a tunnel from a key holder.

## Reliability under hostile networks

- **Blocking UDP wholesale no longer kills a session.** A wholesale UDP block
  (a single `-p udp -j DROP` rule) was the measured failure this design answers
  — 24 retries, 100% loss, one transport. The stream carrier restores message
  boundaries without a cleartext length prefix: each record length is encrypted
  under a per-session key, so the record boundary is not readable and cannot be
  used to segment the stream (`winn3/carrier`).
- **No fragmentation, never.** The inner-IP layer never fragments and never
  reassembles. Oversize packets are dropped and, where possible, a PMTU signal
  is synthesised inward toward the host — it never reaches the wire, because
  inner fragmentation would emit a two-packet burst with a near-fixed size
  ratio and fragments are widely dropped by exactly the middleboxes this
  protocol exists to get past.
- **Sized to the smallest path, on purpose.** A message of L bytes becomes one
  frame and one message of L + 29 bytes on the wire. Sessions are sized to the
  *narrowest* carrier the session may migrate to, across both address families,
  so a failover never silently black-holes full-size flows; the size does not
  shift at the moment of a migration either, which avoids linking the flow
  before a migration to the flow after it.
- **Nothing periodic and nothing distinctive.** Keepalives fire on a silence
  timer, not a fixed interval, and the threshold is redrawn from a truncated
  exponential sampled by inverse CDF so there is no probability atom at the
  truncation bounds. Re-keying and the post-quantum ratchet travel in-band as
  ordinary frames, so a ratchet round does not appear as a distinctive recurring
  packet size. Reconnect delay is exponential with full jitter.
- **Flood work is metered, not amplified.** An unauthenticated datagram costs a
  shard-local lookup and a drop. The expensive admission path is reached only
  after a lookup miss and is metered by a gateway-wide bucket plus a fixed-size
  per-source array — which, being fixed, cannot itself become an exhaustion
  target. `MaxAdmissionHMACs` bounds the reject-path work a misconfigured key set
  could demand.
- **Memory is budgeted.** A registered session earns its full token window by
  opening messages that actually authenticate, rather than all at once; when the
  gateway's token budget is exhausted, windows stop growing, the idlest sessions
  are evicted, and new sessions are refused — silently, like every other
  rejection.

## Claims and the code behind them

| Capability claim | Mechanism in the code |
|---|---|
| Standalone: no AmneziaWG, WireGuard or Xray on the Winn v3 datapath | `winn3/core/doc.go` ("no dependency … and it never will"); the core's import set is stdlib plus `chacha20poly1305`; `winn3/driver`'s `TestDriverIsStandalone` parses imports and fails on `datapath`, Xray or AmneziaWG |
| Own handshake, key schedule, transport crypto | `winn3/core/` (`handshake.go`, `transcript.go`, `session.go`, `keys.go`) |
| No ciphersuite negotiation; fixed suite | `winn3/core/params.go` (`Suite`, `protocolLabel`) — the label is an input to the transcript hash, never sent |
| Two wire shapes only; no cookie/version/error/close message | `winn3/core/doc.go`, `winn3/session/doc.go` (CLOSE is an ordinary frame; a session dying looks like a session working) |
| Transport messages uniform-random to non-participants; no session index/counter/type/length/version on the wire | `winn3/core/doc.go` ("The two shapes on the wire"); `winn3/gateway/doc.go` |
| Admission cost boundary, never integrity; per-gateway | `winn3/core/admission.go`, `winn3/core/doc.go` ("NON-GOAL: the admission layer never contributes to integrity") |
| Freshness bucket never transmitted; anti-replay across restart | `winn3/core/params.go` (`Freshness`), `winn3/core/admission.go` |
| Exact replay protection; reordering tolerance bounded | `winn3/core/replay.go`, `winn3/core/params.go` (`DefaultTokenWindow`, `CallerOwnsTokenWindow`) |
| Post-quantum confidentiality via in-band ML-KEM-768 ratchet | `winn3/session/doc.go` (PQ_EK/PQ_CT frames), `winn3/core/session.go` (`MixPQ`), `winn3/core/params.go` (`Suite`) |
| Gateway never answers an unauthenticated datagram | `winn3/core/doc.go` ("Silence"), `winn3/gateway/doc.go` ("Silence on every rejection path") |
| Flood/unauthenticated work is metered and bounded | `winn3/gateway/guard.go` (bucket + fixed per-source array), `winn3/core/params.go` (`MaxAdmissionHMACs`) |
| Fail-closed carrying gate; drain-barrier teardown | `winn3/tun/gate.go` (`MayCarry` is a whitelist of one; `Gate` is a drain barrier) |
| No fragmentation; floor sizing prevents migration black-holes | `winn3/tun/doc.go`, `winn3/tun/mtu.go`, `winn3/carrier` (`Floor`), `winn3/session/pathmtu.go` |
| Padding defeats fixed-size matching and constant-overhead arithmetic only | `winn3/core/params.go:209-215` (the quoted limitation is the normative scope) |
| Keepalives, re-keying and reconnect are non-periodic and jittered | `winn3/session/jitter.go`, `winn3/carrier/doc.go` ("Fingerprint discipline") |
| Stream carrier survives wholesale UDP block; encrypted record lengths | `winn3/carrier/stream.go`, `winn3/carrier/length.go`, `winn3/carrier/doc.go` ("Why a TCP carrier is not optional") |

## Build and run

```sh
# Go 1.26.5 is pinned by the module toolchain directive.
go test -count=1 ./winn3/...        # the protocol core, session, tun, gateway, carriers
go test -race ./winn3/...           # race detector
./scripts/verify.sh                 # full module gate: vet, race, fuzzing, smoke, reproducible build
```

The full `verify.sh` gate additionally runs parser/signature/frame fuzzing,
the HTTP/3 and HTTP/2 carrier tests, signed-manifest transparency checks,
OpenSSL interoperability, and — where a Docker daemon is available — the
PostgreSQL release gate. Use `-count=1`; Go's test cache can otherwise serve
stale results.

Reference commands that consume the protocol:

- `winn-datapath` — turn a Winn v3 session into an actual tunnel on a host device.
- `winn3-gateway` — the server-side dispatcher (`winn3/gateway`).
- `winn3-conformance` — the cross-host conformance walker (`winn3/conform`).

## Repository layout

```
winn3/core       Pure cryptographic core: handshake, key schedule, transport crypto.
winn3/session    Frame-level session driver: state machine, frames, jitter, padding, path MTU.
winn3/tun        Inner-IP layer: validation, the fail-closed carrying gate, MTU discipline.
winn3/gateway    Server-side dispatch: token index, admission metering, budgets, eviction.
winn3/carrier    Transport carriers: datagram and stream, encrypted record lengths.
winn3/netlab     Impairment rig: exact reorder/drop/delay/flip on real sealed messages.
winn3/conform    Conformance suite pinning cross-host wire vocabulary.
winn3/driver     The loop that joins session, tun and carrier into a tunnel.
```

## License

Winn Protocol v3 is licensed under the **GNU Affero General Public License,
version 3** (or, at your option, any later version) — see
[LICENSE](LICENSE) — with a **separate commercial licence** available from
Win's VPN Inc. for users who cannot or do not wish to comply with the AGPL's
network-use provision. See [COPYRIGHT](COPYRIGHT) for the commercial terms and
contact, [CLA.md](CLA.md) for the contribution terms, and [NOTICE](NOTICE) for
third-party components. The dual-licensing model means third-party code in this
tree must be compatible with both AGPL-3.0 outbound distribution and commercial
relicensing.

SPDX header convention for new files: `AGPL-3.0-or-later`.

Contributions are welcome under the terms of the CLA. Before contributing,
please read [SECURITY.md](SECURITY.md), and — if you are building for a
censorship environment — remember that honest scope is a safety property: a
tool that overstates what it hides endangers the people who rely on it.
