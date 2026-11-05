# Winn Mobility and Censorship-Resistant Carrier

Status: Winn Carrier and Datapath — standalone v3 (WCF3, `winn-datapath/1`, carrier auth v3, control plane wire `winn/2`) + legacy WCF2 carrier. Previous title `experimental v2 implementation contract` was stale; current standalone v3 ships WCF3 (64B, Magic `WCF3`).

> **How this document can lie:** test names, headers, and prose in this tree have repeatedly claimed more than bodies support (nine instances in one day per `CONTINUITY_BRIEF_20260809.md` §4). Verify envelope magic by symbol (`internal/carrier/envelope.go:49` `WCF2`, `internal/wcf3/frame.go:20` `WCF3`) not by hash or count — AGP strips libs so staged hash never appears in APK, and native-marker counts drifted 378→395→396 across identical source.

## Purpose

Winn keeps one logical VPN session alive while the device moves between Wi-Fi,
mobile data, and other underlays, and while individual carrier nodes fail or
become blocked. The encrypted AmneziaWG/WireGuard tunnel remains the end-to-end
data plane. The carrier transports only its UDP packets and cannot decrypt
their inner contents.

The implementation combines:

1. stable logical session state across underlay changes;
2. RFC 9298 HTTP/3 CONNECT-UDP over QUIC DATAGRAM;
3. a bounded length-framed HTTP/2 fallback when QUIC is blocked;
4. RFC 9000 live QUIC path validation and migration;
5. IPv6-first Happy Eyeballs with DNS64/NAT64 support;
6. controller-signed fixed inner-MTU confirmation (fail-closed, no downward search) and bounded handoff redundancy;
7. signed transparent gateway discovery, mandatory ECH, and either
   identity-bound or one-time anonymous authorization.

This is path diversity, not invisibility or guaranteed censorship bypass.
HTTP/2, HTTP/3, timing, volume, and endpoint IPs remain observable and can be
blocked.

## Bootstrap and authentication

Outside explicit `-lab-mode`, both client and carrier verify the same current
gateway manifest. The manifest is ML-DSA signed, valid for no more than seven
days, included in a signed append-only receipt chain, and checked against an
externally retained checkpoint. It binds the controller, hybrid suite, nodes,
MASQUE/H2 endpoints, TLS name, ECH configuration, inner-MTU cap,
authorization modes, and optional blind-token keys. Direct endpoint flags
cannot override it.

Every public TLS connection uses TLS 1.3, exactly one configured
ECDHE+ML-KEM group, a fresh handshake, mandatory RFC 9849 ECH, and the expected
ALPN. Resumption and 0-RTT are disabled.

The manifest selects one carrier authorization mode:

- `identity`: P-384 mTLS identifies the device, and the request carries a
  registered device ML-DSA signature.
- `anonymous-token`: the client presents no stable certificate. It redeems a
  one-time RFC 9474 RSA blind-signature token and proves possession of the
  fresh ephemeral ML-DSA key committed into that token.

The separate issuer uses hybrid mTLS, ECH, and the registered device ML-DSA key
to authorize a blinded request. It cannot see the completed token. The carrier
can verify and consume the token but does not receive the issuer's device
identity or issuance log. A private token bundle is consumed for each carrier
attempt; inventory exhaustion fails closed. This separation reduces linkability
but cannot defeat collusion, timing correlation, or endpoint-level traffic
analysis.

Every request binds its authorization mode, manifest digest, session, sequence
epoch, carrier, authority/path, logical UDP target, timestamp, nonce, suite,
negotiated MTU, and purpose. Every successful response is signed by the
manifest-pinned controller key and echoes that purpose. Replay nonces and token
serials are bounded and single-use.

H3 preparation uses the signed `authenticate-only` purpose. The carrier
verifies and consumes the one-time credential, returns its controller-signed
response, records the event, and terminates that request server-side without
opening an AWG backend socket. The retained QUIC/TLS connection is then used by
a separate click-bound `data` request with a new credential. Only `data` may
allocate the fixed backend and it must still complete MTU and tunnel
verification before route/DNS commit.

The short click-binding expiry bounds candidate work; it does not terminate an
already committed carrier. A live H3 path instead inherits a separately frozen
session-trust expiry from the earliest signed descriptor, manifest, PSK,
credential, and underlay-authorization lifetime. Migration after the connect
window uses the exact original binding as session identity while checking the
session-trust expiry. It never treats an expired click binding as authority to
construct a fresh connection.

The server ignores the network destination requested by the client and sends
only to its configured AWG UDP backend. The public target is an exact logical
sentinel. Winn is never an open proxy.

## Session and sequence continuity

One VPN-service instance creates a random 128-bit Winn session ID and a random
128-bit sequence epoch (32 lowercase hex, validated by `mobility.ValidSessionID`; WCF3 wire carries 64-bit epoch inside the `connectivity.Binding` context derived from this value). Carrier changes preserve:

- Winn session ID and sequence epoch;
- AWG interface and peer keys;
- current AWG PSK generation;
- routes, DNS policy, and kill-switch state.

Every data envelope carries a monotonically increasing sequence number. H3 and
H2 share the same sequence space, so the server can discard duplicates during
handoff. A new client process creates a new sequence epoch, preventing sequence
reuse under a retained session identifier. AWG rekeying is a separate
authenticated operation and is never coupled to carrier recovery.

## Live QUIC migration and carrier replacement

The H3 implementation owns explicit QUIC transports with eight-byte connection
IDs. When a platform adapter supplies a UDP socket bound to a new underlay,
Winn starts RFC 9000 path validation on the existing connection, waits for the
PATH_CHALLENGE/PATH_RESPONSE probe, switches only after success, and retains
both sockets until connection teardown. Failed validation leaves the current
path unchanged.

Migration changes the path of one live H3 connection. Carrier replacement
creates and authenticates a new H3 or H2 connection, then atomically installs
it. During an optional handoff window, Winn duplicates at most 128 data
datagrams for at most one second with identical sequence numbers. The server
delivers only one copy. This is bounded make-before-break protection, not
always-on simultaneous multipath.

The IETF multipath QUIC specification remains a draft and the selected QUIC
stack does not provide a production simultaneous-path scheduler. Winn therefore
does not claim draft multipath-QUIC conformance.

## Selection and recovery

Each path has an exponentially weighted RTT and loss estimate. Selection uses:

`priority + latency + loss + failure penalty - throughput benefit`

Hysteresis and a switch cooldown prevent flapping. A failed active path becomes
immediately ineligible. Recovery uses bounded exponential backoff with
cryptographic jitter and rotates through every signed manifest node and carrier
type. IPv6 candidates begin first; IPv4 begins after a short fallback delay.
Signed IP hints can avoid DNS latency, and a configured DNS64 prefix can
synthesize NAT64 addresses for IPv4-only origins on IPv6-only networks.

The default order is:

1. H3 CONNECT-UDP for datagram semantics and reduced head-of-line blocking;
2. H2 framed streaming as the blocked-QUIC fallback.

Deployments may reverse this order. Native direct AWG remains the
lowest-overhead option outside this carrier, but it is never an automatic
fail-open path.

## Envelope, MTU, and privacy profile

Legacy carrier envelope is WCF2 (`envelopeMagic="WCF2"`, `internal/carrier/envelope.go:49`, 16-byte header: magic 4 + kind 1 + zero 1 + length 2 + sequence 8) and carries a type, sequence number, logical payload length, and optional length-bucket padding. Types include data, authenticated MTU probe/ack, and cover. Standalone v3 is WCF3 (`Magic="WCF3"`, `internal/wcf3/frame.go:20`, 64-byte header: magic 4 + kind 1 + flags 1 + length 2 + SessionID 16 + BindingID 16 + PSKGeneration 8 + SequenceEpoch 8 + Sequence 8) which binds every frame to one verified connection attempt. H2 adds an unsigned 16-bit network-order frame length on the carrier side. Parsing is bounded and trailing, malformed, oversized, duplicate, and out-of-window frames fail closed.

The inner AWG interface MTU is controller-signed and fixed for the session, so
neither carrier searches downwards: it confirms the signed size or the
coordinator selects a different carrier. A smaller acknowledgement is not a
usable result.

**H3 sends no MTU probe.** Client and server both pin the QUIC
`InitialPacketSize` to `H3InitialPacketSize(maxOuter)` (`maxOuter + 64`), and
quic-go pads every client Initial packet to that size, so a *completed QUIC
handshake* is already proof that the path carried a datagram larger than a
full-size Winn envelope — in both directions, since the server's own first
flight is padded to the same floor. The carrier therefore reads the capacity
quic-go has already established, which costs zero packets, and fails closed if
it is short. This replaced an authenticated inner-MTU probe whose *failure* was
the problem: an adversary who dropped the client's datagrams of the envelope's
size class could induce a burst of same-size datagrams and a connection teardown
on demand. See `TestQUICHandshakeAlreadyProvesTheCarrierPath`, which measures
the padding claim against the vendored quic-go rather than asserting it.

**H2 still exchanges exactly one full-size envelope**, and fails closed if it is
not acknowledged. TCP offers no path MTU to discover and no handshake-derived
datagram size to read, so nothing else on that carrier shows the tunnel is wired
end to end at full size. It is one datagram, not a retry schedule: over a
reliable ordered stream an application-level retransmission cannot deliver
anything TCP has not already delivered, so retries bought nothing and cost the
same inducible pattern. The residual on H2 is one full-size record followed, if
it is not answered, by a closed HTTP/2 request after roughly 1.2–2.0 s.

H3 also enables QUIC datagram packetization-layer PMTU discovery, which is
quic-go's own and is ordinary QUIC behaviour. The default maximum inner datagram
is 1,350 bytes and the absolute maximum is 1,500; deployment operators must
still validate the actual AWG interface MTU on IPv4 and IPv6.

Length-bucket padding and jittered keepalives are **on by default**, in both
directions. They are what the `high-risk` privacy profile selects, and that
profile is the default; `standard` turns padding off and puts inner datagram
lengths on the wire 1:1. The carrier library's own default matches, so an
embedder that constructs a dialer and says nothing about padding still gets it
— see `EnvelopeConfig.DisableLengthPadding`. Cover traffic requires a second
explicit flag and uses
bounded size and intervals of at least 500 ms to limit battery and metered-data
cost. Padding and cover traffic reduce simple size/timing classification only;
they cannot conceal endpoint IPs, long-term volume, active probing, or a
compromised carrier.

## Platform integration

Core datapath and carriers are pure Go with `CGO_ENABLED=0` and build for Linux amd64/arm64, Android arm64, macOS arm64, and Windows amd64. Apple C-ABI delivery (`cdatapath` static archive `libwinn_datapath.a` and `cshared`) requires `CGO_ENABLED=1` (see `cdatapath/winn_datapath.go:6`). Platform adapters provide bound UDP/TCP sockets and network-change signals:

- Android `Network.bindSocket`;
- Apple Network Extension path-bound sockets;
- Windows interface selection;
- Linux policy routing or `SO_BINDTODEVICE`.

The tested library hook accepts a replacement bound UDP socket for live H3
migration. Shipping-platform integration remains a deployment gate; this
isolated experiment does not modify the Win's VPN app.

## Operational signals

Implementations expose counters for authenticated connections, authorization
failures, replay/token rejection, ECH rejection, carrier dial failure, path
switch/migration, recovery, MTU reduction, duplicate suppression, and oversized
packet drops — measured names include `h3_authenticated`, `carrier_dial_failed`, `carrier_recovered`, `carrier_probe_failed`, `carrier_path_switched`, `carrier_quic_migrated`, `carrier_quic_migration_failed`, `carrier_handoff_datagram_duplicated`, `carrier_active_failed`; no metric literally named `fail-closed intervals` was found (grep of `Metrics.Inc` sites). Logs never contain packet payloads,
private keys, token secrets, PSKs, or signatures.

Both carriers additionally emit the sealed terminal-event trail specified in
`SPECIFICATION.md` section 9.1: a per-request correlation identity minted at
the redemption boundary, one `authenticated` record, and exactly one mutually
exclusive terminal record of class `auth_only`, `open`, or `aborted`, so a
request that fails after a durable token redemption cannot leave the audit
trail without a terminal class. The abort-reason enum is closed and versioned;
an unrecognised reason fails verification rather than being accepted.

## Standards

- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9298: CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298.html)
- [RFC 8305: Happy Eyeballs v2](https://www.rfc-editor.org/rfc/rfc8305.html)
- [RFC 8899: Datagram PLPMTUD](https://www.rfc-editor.org/rfc/rfc8899.html)
- [RFC 9474: RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html)
- [RFC 9849: TLS Encrypted ClientHello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [Multipath QUIC Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/)
