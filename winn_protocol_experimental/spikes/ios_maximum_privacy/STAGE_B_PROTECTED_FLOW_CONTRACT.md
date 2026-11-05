# Winn iOS privacy spike — Stage B protected-flow contract

Status: local conformance design; not physical or usable-VPN evidence  
Protocol: `winn/3`  
Wire schema: `winn-stageb-reflector-wire/1`  
Receipt scope: `local-conformance-only`

Stage A proves only that iOS reports the experimental Packet Tunnel as
connected. Stage B is a separate gate for the first protected flow. Nothing
produced by the offline implementation or loopback reflector may be described
as a physical result, a working VPN, or time-to-first-protected-packet.

## Success predicate

A Stage B attempt succeeds only when one attempt lease, one WCF3 connection
context, and one local monotonic deadline bind all of the following:

1. a fresh AWG handshake;
2. nonzero authenticated outbound and inbound tunnel bytes;
3. a protected-DNS response through the winning tunnel; and
4. one authenticated reflector response for the attempt's tunnel-only canary.

Every predicate must be recorded at or before
`requestedAtMonotonicNanoseconds + 3_000_000_000`. Exactly three seconds
passes; three seconds plus one nanosecond fails. Timeout, cancellation,
supersession, or any mismatch produces a terminal clean failure and makes all
later events for that lease no-ops.

The state model must reject zero byte counts, duplicate/conflicting predicate
events, reversed timestamps, overflow, events after the deadline, events from
another attempt/lease, and events with a different WCF3 session ID, binding ID,
PSK generation, or sequence epoch. It must not emit success until all four
predicates are present. For the canary response specifically, the ordering is:

```text
lease requested-at <= request-sent <= response-observed <= lease deadline
```

The reflector predicate may be recorded only by the serialized attempt owner
after it consumes an authenticated, exact-request-bound response proof. A bare
Boolean, binding, timestamp, or separately mutable response-acceptor state is
not sufficient.

## Binary reflector wire format

All integers are unsigned big-endian. All offsets and lengths are fixed. UUIDs
are the 16 RFC 4122 bytes, not text. SHA-256 values and the challenge are raw
32-byte values. Reserved bytes must be zero.

### Common request body — 222 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | ASCII magic `WBR3` |
| 4 | 1 | wire version `1` |
| 5 | 1 | message type: `1` request, `2` response |
| 6 | 2 | reserved zero |
| 8 | 6 | ASCII protocol `winn/3` |
| 14 | 16 | run ID |
| 30 | 16 | attempt nonce |
| 46 | 32 | source SHA-256 |
| 78 | 32 | artifact SHA-256 |
| 110 | 16 | WCF3 session ID |
| 126 | 16 | WCF3 binding ID |
| 142 | 8 | PSK generation, greater than zero |
| 150 | 8 | sequence epoch, greater than zero |
| 158 | 8 | canary sequence, greater than zero |
| 166 | 8 | issued-at Unix milliseconds |
| 174 | 8 | expires-at Unix milliseconds |
| 182 | 8 | request-sent local monotonic nanoseconds, echoed opaque by reflector |
| 190 | 32 | random challenge, not all zero |

The request is exactly 254 bytes:

```text
common request body with type=1 ||
HMAC-SHA256(key, "winn-stageb-request/v1\0" || common request body)
```

The response is exactly 302 bytes:

```text
common request body with type changed to 2 ||
32-byte request tag ||
8-byte reflector-received Unix milliseconds ||
8-byte reflector-sent Unix milliseconds ||
HMAC-SHA256(
  key,
  "winn-stageb-response/v1\0" ||
  every preceding response byte
)
```

The shared key is exactly 32 bytes. It is test-only in the offline harness and
must never appear in receipts, evidence records, logs, errors, or packet
metadata. The client acceptance domain owns this key and the exact outbound
request tag for each attempt. Response callers cannot supply or replace the key
at acceptance time, and the reflector predicate must not be reachable through
a public stateless response-verification API.

## Validation and replay rules

The reflector accepts only exact-length request datagrams. It verifies every
fixed field and the request HMAC before consulting the replay cache. Source and
artifact digests, both UUIDs, session ID, binding ID, and challenge must not be
all zero. The expiry must be later than issue time, the lifetime must be at
most 10,000 milliseconds, and the injected reflector clock must be within the
closed interval `[issuedAt, expiresAt]`.

The replay key is the verified request tag. One verified request may produce
one response. A second use before or after expiry is rejected. Replay entries
may be removed only after expiry. The loopback implementation must have a
bounded cache and fail closed when full; it must not evict a live entry to
accept a new request. A cache accepts at most 4,096 entries and maintains a
nondecreasing clock watermark. A clock value below that watermark fails closed,
so pruning an expired entry followed by wall-clock rollback cannot make its
tag admissible again.

The client verifies exact response length, fixed fields, request-tag echo,
reflector timestamp order, response HMAC, the complete expected request
binding, the active attempt lease, and its local monotonic deadline. A response
for a cancelled or superseded attempt/path is rejected even if its HMAC is
valid. A response tag may be accepted only once by the shared acceptance
authority, including across distinct attempt objects. Cancellation,
supersession, mismatch, or failed verification terminalizes the same serialized
attempt owner that records the other Stage B predicates; later inputs cannot
repair or revive it. The shared acceptance authority captures its processing
timestamp from an injected trusted monotonic clock while holding its own replay
lock. It must not advance a global watermark from caller-supplied observation
timestamps: distinct valid responses that were observed in one order but
scheduled into the authority in another must not be rejected as clock
rollback. The authority's internally captured time is the reflector-predicate
time and must satisfy the ordering and deadline above.

Authentication comparisons use constant-time equality. Errors identify only a
field/category and must not contain the key, tag, challenge, client address,
Apple identifier, or any packet body.

## Loopback-only reference boundary

The Go reference server may bind only literal loopback addresses
`127.0.0.1` or `::1`. Wildcard, hostname-resolved, unicast, multicast, and
unspecified addresses are rejected. It handles one datagram at a time through
the pure codec/validator and returns the authenticated response to the source
socket. It never forwards traffic and never logs or persists client
identifiers.

## Cross-language gate

Go owns the canonical fixture file
`stagebreflector/testdata/stageb-v1-vectors.json`. It contains only a public
test key and deterministic non-secret inputs, exact request/response base64,
and expected SHA-256 values. Swift and Go must consume the same fixture bytes.

The local gate requires:

- exact request and response byte equality in Swift and Go;
- valid request/response acceptance;
- every field-binding mutation rejected;
- wrong key and tag mutations rejected;
- replay and cache-capacity rejection;
- shared response-replay rejection across two attempt objects;
- replay rejection after expiry/pruning followed by clock rollback;
- two distinct valid responses remain admissible when caller scheduling order
  differs from their earlier callback/observation order;
- stale, future, overlong-lifetime, and reversed reflector-time rejection;
- response-observed-before-request-sent rejection;
- exactly 3 seconds accepted and 3 seconds + 1 nanosecond rejected;
- cancelled and superseded-path responses rejected;
- oversized/truncated/trailing-byte datagrams rejected;
- errors and emitted local receipts free of key, tag, challenge, address, and
  client-identifier material.

Passing this gate means only that the two local implementations agree on the
Stage B contract. Physical iPhone integration, a remote disposable reflector,
real AWG/DNS predicates, energy, radio/path changes, and first protected packet
remain separate acceptance gates.
