# Stage B iOS App-Probe Integration Contract

Status: implementation prerequisite; no physical result is claimed.

## Purpose

The Stage B latency endpoint is the first complete, authenticated protected
flow, not Packet Tunnel activation. The containing app must originate the inner
DNS and reflector datagrams. A socket created by the Packet Tunnel extension
cannot be assumed to re-enter its own tunnel and is therefore inadmissible as a
protected-flow source.

The private DNS resolver and private reflector use numeric overlay addresses
that are reachable only through the selected AWG tunnel. No public address,
hostname fallback, alternate route, or extension-originated probe is allowed.
An independently captured outer-path trace must contain neither plaintext
probe.

## One serialized attempt

One provider-owned serial queue owns:

- the exact `wgTurnOn` handle and one discovered utun file descriptor;
- the canonical lowercase UUIDv4 CSPRNG engine-instance nonce and opaque
  interface token;
- engine and path generations;
- the SHA-256 of the exact configuration bytes passed to `wgTurnOn`;
- the SHA-256 of the exact signed AWG runtime binary loaded by the extension,
  separately from the immutable unsigned source-artifact SHA-256;
- the shared monotonic clock authority and Stage B coordinator;
- one immutable attempt nonce, first-click T0, deadline, WCF3 binding, expected
  peer, AWG configuration digest, DNS probe, and reflector request;
- every pre/post `wgGetConfig` snapshot and terminal transition.

The host owns one matching latch and the exact
`NETunnelProviderSession`. Neither side may rediscover the session, reset T0,
replace the attempt nonce, or continue after supersession or a terminal state.
Every UAPI sample carries and is checked against the complete **runtime**
engine/path identity represented by physical attempt schema `/2`: signed
runtime binary, actual configuration, expected peer, engine nonce and
generations, winning path generation, and opaque interface-token digest. The
immutable unsigned source-artifact digest is a separate build-receipt
provenance pin; it is not overloaded into `/2` sample identity. Adding it to
the physical JSON would require a future schema revision. Caller-asserted
digests or identity fields that are not derived from the same owned start
operation are inadmissible.

The AWG dynamic library remains loaded for the provider process lifetime.
`dlclose` is forbidden because the pinned upstream Apple engine initializes
process-lifetime support work. The attempt may stop only its owned AWG handle.

## Start chronology

1. The Start button's literal first operation captures T0.
2. The host installs its notification observer and sends the existing Stage A
   and separate Stage B start-option namespaces with the same nonce.
3. The provider's literal first `startTunnel` operation captures its receipt
   time and validates `T0 <= hostRequest <= providerReceipt`.
4. The provider applies full-tunnel settings, identifies exactly one utun
   candidate, duplicates or otherwise pins its descriptor, revalidates the
   pinned descriptor immediately before use, starts the pinned AWG engine on
   that exact descriptor, and takes a same-handle baseline UAPI snapshot.
   Discovery followed by use of an unpinned file-descriptor number is
   inadmissible.
5. Only after the baseline and coordinator exist may the provider complete
   `startTunnel`. `NEVPNStatus.connected` remains an intermediate activation
   event, not Online.
6. The host immediately begins the protected probe sequence on the same
   captured session. All work still shares the original `T0 + 3 seconds`
   deadline.

## Fixed, bound host-provider messages

Stage B messages use a fixed binary codec with exact lengths and versions.
Permissive JSON is forbidden. Every request and response binds:

- schema and message kind;
- attempt nonce and monotonically increasing message sequence;
- path ID and binding SHA-256;
- original T0 and deadline;
- a per-message challenge or the exact digest of the preceding message.

Unknown versions, lengths, kinds, reserved bits, duplicates, stale sequences,
nonce/path/binding mismatches, nonzero reserved bytes, or replies after
supersession/terminal state fail the attempt. A bounded provider round trip has
one completion authority; a late callback is ignored and cannot act on a later
attempt.

## DNS proof

1. Before replying to `prepare-dns`, the provider captures the exact peer's
   same-handle pre-send snapshot. This prepares the send but does **not** record
   a request-send proof.
2. The reply carries one precommitted raw DNS query:
   a nonzero transaction ID, one unique CSPRNG nonce label, one exact question,
   and the numeric tunnel-private resolver endpoint. The query and expected
   response bytes/digests were committed before connection work.
3. The containing app sends exactly that UDP payload to exactly that numeric
   overlay endpoint. It must not call a public resolver or retry another
   endpoint/protocol.
4. Only after the UDP send API reports successful ownership/acceptance of the
   exact datagram does the app send a separate bound `dns-sent`
   acknowledgement to the provider. On receiving that acknowledgement, the
   provider samples its own monotonic clock and records the request-send proof.
   A host timestamp may be diagnostic metadata but is never acceptance
   authority.
5. The app then returns the exact bounded DNS response bytes in a later bound
   `dns-response` message. The provider samples its own monotonic clock when it
   accepts that message; a host receive time cannot establish timeliness.
6. The provider validates the DNS wire response, question, transaction ID,
   nonce, expected answer and response digest, then captures a same-handle post
   snapshot. Strict transmit and receive counter movement from the recorded
   pre-snapshot is mandatory.

The unique name prevents cache reuse. A response before `dns-sent`, without
the pre-send proof,
without exact post-snapshot bidirectional movement, or observed outside the
original deadline is inadmissible.

## Reflector proof

1. Only after accepting DNS does the provider handle `prepare-reflector`,
   capture a same-handle pre-send snapshot, and return the coordinator's exact
   authenticated reflector request plus the one numeric tunnel-private
   endpoint. Preparing this response does not record a send proof.
2. The app sends exactly one bounded UDP request to that endpoint. Only after
   the UDP send API reports successful ownership/acceptance of the exact
   datagram does the app send a separate bound `reflector-sent`
   acknowledgement. The provider samples its own monotonic clock when it
   records the send proof.
3. The app returns the exact response bytes in a later bound
   `reflector-response` message. The provider samples its own monotonic clock
   for acceptance; host timestamps remain non-authoritative diagnostics.
4. The provider captures a same-handle post snapshot, requires strict
   bidirectional counter movement, validates the remote response with the
   shared acceptance domain and replay cache, and records the reflector
   predicate.

No hostname resolution, public endpoint, transport fallback, or second engine
is allowed inside this physical acceptance attempt.

## Success and failure

Success requires all four provider-owned predicates on the exact binding:

1. fresh AWG handshake;
2. authenticated bidirectional AWG byte movement;
3. protected DNS response;
4. authenticated private-reflector response.

The provider captures `tData` immediately after the final predicate and returns
one bound terminal response. The host captures `tUI` when the main actor
actually commits Online. Success requires every predicate, `tData`, terminal
time, and `tUI` to be no later than `T0 + 3,000,000,000 ns`.

The provider and host each arm an independent timer using the same absolute
deadline. An ordinary error cannot borrow the deadline-failure reporting
window. A true deadline failure follows physical attempt schema `/2`: terminal
timer wake in `(deadline, deadline+50 ms]`, UI no earlier than terminal and no
later than `deadline+50 ms`, and cleanup independently by
`terminal+250 ms`.

The first terminal transition wins. Stop, timeout, cancellation, path change,
engine change, network-settings change, or a binding mismatch securely stops
the owned handle exactly once and makes every late callback a no-op.

## Required tests before the iPhone run

- fixed-codec golden vectors plus every field/length/reserved/version mutation;
- duplicate, stale, reordered, cross-attempt and late host-provider messages;
- responses before their matching send acknowledgement, duplicate/mutated
  acknowledgements, and prepare-without-send timeout;
- host/provider deadline, reply/timeout, cancellation and supersession races;
- exact same-handle snapshots around both app-originated probes;
- zero/multiple utun candidates and path-generation changes;
- descriptor reuse between discovery and start, failed descriptor duplication,
  and failed pre-use revalidation;
- every change to the seven runtime identity fields (signed runtime,
  configuration, expected peer, UUIDv4 engine nonce, engine generation, path
  generation, and opaque interface-token digest) between any two samples;
- unsigned source-artifact/build-receipt provenance drift as a separate build
  gate, without treating that provenance pin as a `/2` per-sample field;
- private-only endpoint enforcement and public/hostname/fallback refusal;
- DNS cache, transaction, nonce, question, answer and digest mutations;
- reflector authentication, replay, sequence and endpoint mutations;
- no plaintext DNS/reflector payload in the outer-observer fixture;
- exact three-second and plus-one-nanosecond success boundaries;
- bounded deadline-failure reporting and exactly-once cleanup.

Simulator tests prove only codec, lifecycle, build, and controlled routing
logic. Only an owner-consented physical iPhone run with an independently
observed outer path can prove the protected-flow claim.
