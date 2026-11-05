# Winn Protocol v2 Specification — CONTROL-PLANE REKEY ONLY; NOT STANDALONE v3

Status: production-candidate reference protocol for the **v2 control-plane rekey** (AmneziaWG PSK rotation). Wire version: `winn/2`. **This file does not specify the standalone Winn Protocol v3 datapath.**

> **Standalone v3 is documented separately** and is not an extension of this file. The owning design is `docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md`; the implementation is `winn3/core` (handshake/crypto), `winn3/session` (driver, liveness, path-MTU notice `W3PM`), `winn3/gateway` (front door with path-MTU notice `notice []byte`), `winn3/tun` (inner-IP validator, Overhead 29, floors 576/1280, dead zone 1280–1420), `winn3/driver` (Sizing/plan floor, `carrier.DefaultPathMTU=1450`), `winn3/conform` (cross-host derivation + resolver guards), and `internal/gatewaymanifest/manifest_v2.go` (`winn-gateway-manifest/v2`). See audit `docs/handoff/SPEC_AUDIT_20260812_doc_specification.md` for a claim-by-claim assessment. Any citation of this file as authority for the gateway datapath descriptor resolver is incorrect — that resolver is defined in `winn3/conform` (`Standalone*ResolverGuards`, `inner_resolver_v4`).

Normative words such as MUST and MUST NOT are used in their usual standards
sense.

## 1. Scope

Winn v2 is an authenticated control-plane exchange that rotates the optional
256-bit preshared key of one AmneziaWG/WireGuard peer. AWG remains the data
plane for v2. Winn's separately versioned v2 carrier extension may transport AWG
datagrams and preserve logical session continuity. Routing, accounts, billing,
application UI, and censorship-resistance guarantees are outside this
specification. **Standalone v3 owns its handshake, crypto and datapath and transports inner IP directly (DemuxToken || AEAD(frames)), with no AWG PSK, no TLS 1.3, and no HTTP rekey — see v3 docs above. This scope does not cover v3.**

## 2. Cryptographic profile

A Winn endpoint MUST select one suite:

| Suite identifier | TLS 1.3 named group | ML-DSA authentication |
|---|---|---|
| `x25519-mlkem768` | `X25519MLKEM768` (4588) | ML-DSA-65 |
| `p256-mlkem768` | `SecP256r1MLKEM768` (4587) | ML-DSA-65 |
| `p384-mlkem1024` | `SecP384r1MLKEM1024` (4589) | ML-DSA-87 |

The connection MUST use TLS 1.3, the endpoint's one named group, mutual X.509
authentication, ALPN `http/1.1`, and an accepted RFC 9849 ECH offer. TLS
resumption is disabled so every rotation obtains a fresh hybrid exchange. The
implementation MUST abort on any ECH, version, group, or ALPN mismatch and MUST
NOT offer a classical-only or public-ClientHello fallback.

X.509 keys in this reference are P-384 ECDSA. X.509 authentication is necessary
but not sufficient: every request and successful response MUST also carry the
suite-mapped ML-DSA signature.

ML-DSA operates in pure mode with context string `Winn-Protocol-v2`.
Signatures are randomized. Implementations MUST therefore use the unsigned
canonical message, not signature bytes, for idempotency.

## 3. Identities and trust

The device certificate MUST have an authenticated URI SAN:

`spiffe://winn.local/device/<device-id>`

`device-id` and `controller-id` are 1–64 ASCII characters matching
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. The request's `device_id` MUST match the
certificate URI identity. `controller_id` is a stable audience and MUST match
the configured endpoint.

The controller registry binds a device ID, ML-DSA algorithm, and public-key ID.
The device pins the equivalent controller key tuple. A key ID is lowercase
SHA-256 hex over:

`"winn-pq-auth-key/v2\0" || algorithm || 0x00 || raw_public_key`

The registry/pin formats allow up to four simultaneous keys per algorithm so a
new key can be distributed before the old one is retired.

## 4. HTTP exchange

- Method and path: `POST /v2/rekeys`
- Request `Content-Type`: `application/vnd.winn.rekey+json;version=2`
- Request `Accept`: `application/vnd.winn.rekey+json;version=2`
- Content encoding: forbidden
- Maximum request and response JSON: 32 KiB
- Query parameters, redirects, unknown JSON fields, trailing JSON values, and
  non-canonical encodings: rejected
- Responses: `Cache-Control: no-store`

### 4.1 Request

```json
{
  "version": "winn/2",
  "suite": "x25519-mlkem768",
  "controller_id": "winn-controller-1",
  "device_id": "device-1",
  "peer_public_key": "<canonical-base64-32-bytes>",
  "request_id": "<base64url-no-padding-32-bytes>",
  "nonce": "<base64url-no-padding-32-bytes>",
  "current_generation": 0,
  "capabilities": ["..."],
  "auth_algorithm": "mldsa65",
  "auth_key_id": "<64-lowercase-hex>",
  "auth_signature": "<canonical-base64>"
}
```

`peer_public_key` MUST decode to 32 non-zero bytes. `request_id` and `nonce`
MUST each encode 32 random bytes. `current_generation` is the last generation
durably applied by the device, initially zero. Its maximum valid value is
9,223,372,036,854,775,806; the next and final response generation is
9,223,372,036,854,775,807. This signed-`bigint` ceiling keeps file and
PostgreSQL state semantics identical and prevents narrowing conversion.

Required capabilities are:

- `mutual-x509-auth`
- `awg-preshared-key-32`
- `monotonic-key-generation`
- the selected `tls13-...` suite capability
- `dual-auth-x509-mldsa65` or `dual-auth-x509-mldsa87`

Duplicate or empty capabilities are invalid.

The ML-DSA request message is:

`"Winn-Protocol-v2/request\0" || canonical_unsigned_request_json`

The unsigned JSON uses the field order shown above and omits only
`auth_signature`; it includes `auth_algorithm` and `auth_key_id`. The
controller MUST verify the certificate identity, registry lookup, key ID, and
signature before preparing a key.

### 4.2 Response

New success returns `201 Created`; an exact idempotent retry returns `200 OK`.

```json
{
  "version": "winn/2",
  "suite": "x25519-mlkem768",
  "controller_id": "winn-controller-1",
  "device_id": "device-1",
  "peer_public_key": "<request value>",
  "request_id": "<request value>",
  "nonce": "<request value>",
  "generation": 1,
  "key_id": "<64-lowercase-hex>",
  "preshared_key": "<canonical-base64-32-bytes>",
  "issued_at": "<RFC3339Nano UTC>",
  "expires_at": "<RFC3339Nano UTC>",
  "capabilities": ["..."],
  "auth_algorithm": "mldsa65",
  "auth_key_id": "<64-lowercase-hex>",
  "auth_signature": "<canonical-base64>"
}
```

The PSK MUST be 32 non-zero random bytes. Lifetime MUST be at least one minute,
no more than 30 days, and unexpired when the device validates it. A client
allows at most five minutes of future clock skew for `issued_at`.

The ML-DSA response message is:

`"Winn-Protocol-v2/response\0" || canonical_unsigned_response_json`

The unsigned response uses the field order shown and omits only
`auth_signature`. It includes the PSK and every request/generation binding. The
device MUST select the pinned key by algorithm and key ID, verify ML-DSA, then
validate all logical bindings before exposing the PSK to its tunnel adapter.

`key_id` is the lowercase SHA-256 hex digest of:

`"winn-awg-psk-id/v2\0" || controller_id || 0x00 || suite || 0x00 || device_id || 0x00 || peer_public_key || 0x00 || uint64_be(generation) || 0x00 || psk`

It is an identifier, not a secret or key derivation function.

## 5. Replay and state machine

The request digest is:

`SHA-256("winn-rekey-request-digest/v2\0" || request_signing_message)`

It excludes the randomized signature bytes but includes the signer key ID and
every security-relevant request field.

For each `(controller_id, device_id, peer_public_key)`:

1. The request generation MUST equal the committed controller generation.
2. The controller durably stores one prepared response and marks its request
   pending.
3. The controller applies that exact PSK to the AWG peer.
4. The controller durably commits the generation.
5. The controller returns the stored signed response.
6. The device applies the identical PSK.
7. Only after apply succeeds does the device durably clear its pending request
   and advance its generation.

The bootstrap endpoint MUST remain reachable independently of the peer being
rotated. Until the device commits locally, it MUST retry the exact persisted
request. An exact request receives the exact stored response and PSK. Reusing a
request ID with different content, using a stale generation, or preparing a
different request while one is pending MUST fail closed.

A crash after controller apply but before commit is recovered by reapplying the
same PSK and committing it. No automatic rollback is performed. If a device
permanently loses its pending request, an administrator may clear only the
exact `(device, peer, request_id)` preparation after operational
reconciliation; this deletes the uncommitted response without changing the
committed generation.

## 6. State backends

### 6.1 Single-node file

The complete state is encrypted with AES-256-GCM under a separate random state
key, written through fsync plus atomic rename, and guarded by a non-blocking
exclusive OS file lock. Mutations are copy-on-write: a failed disk write does
not alter live state. A second controller MUST fail to open the same state.

### 6.2 PostgreSQL

Multi-controller state uses serializable transactions and transaction-scoped
advisory locks over request and peer identities. Response/PSK JSON is encrypted
with AES-256-GCM and associated with the controller and request before database
storage. Runtime connections require `sslmode=verify-full`; a non-TLS loopback
exception exists only under explicit lab mode. Production schema migration is
separate from runtime startup.

## 7. AWG adapter

The command adapter invokes, without a shell:

`<absolute-awg-binary> set <interface> peer <public-key> preshared-key <private-temp-file>`

The binary MUST be a regular executable and the interface must match the
implementation's restricted identifier grammar. The temporary directory is
private, the PSK file is mode `0600`, process output is not logged, and the file
is removed immediately. Mobile applications MUST use native protected
storage/tunnel APIs rather than the lab file adapter.

## 8. Errors and availability controls

Errors are JSON `{code,message}` with non-secret stable codes. Authentication,
registry, revocation, replay, generation, media, size, audit, storage, and AWG
apply failures are fail-closed. Rate-limit responses use 429 and `Retry-After`;
capacity or dependency failures use 503.

The reference server applies a bounded per-device/IP token bucket and a hard
concurrent request ceiling. Its health/ready/metrics listener accepts only a
numeric loopback bind. An unhealthy audit sink makes the protocol endpoint
unready and unavailable.

## 9. Audit

Security events are JSONL records with sequence, timestamp, event, keyed device
hash, request ID, detail, previous MAC, and HMAC-SHA-256 authentication. Each
record is appended and fsynced. Startup verifies sequence and the entire MAC
chain. Audit and state keys MUST be distinct. The chain detects record edits and
internal reordering/deletion, but suffix truncation requires a separately
retained checkpoint. It does not replace remote log replication or an offline
signature/checkpoint policy.

### 9.1 Carrier terminal-event conservation

A carrier request that presents a valid single-use privacy token creates a
durable redemption row before the carrier has produced any HTTP result. Such a
request MAY fail afterwards, but it MUST NOT disappear from the audit trail.

Immediately after redemption a carrier MUST mint a correlation identity of 128
bits from the system CSPRNG, rendered as 32 lowercase hexadecimal characters,
and MUST place it in the audit `request_id` field of every record it writes for
that request. The correlation identity MUST NOT be derived from client-supplied
claims: a session identity is stable across several requests and cannot
separate two redemptions, and a client-chosen request nonce can be made to
collide deliberately.

Every carrier audit record belonging to an authenticated request MUST carry the
versioned five-token detail encoding, in this exact order:

```
carrier-terminal/v1 class=<class> mode=<mode> session=<session> reason=<reason>
```

`class` is one of `authenticated`, `auth_only`, `open`, `closed`, `aborted` and
MUST agree with the record's event name. `mode` is the authorization mode.
`session` is the 32-hexadecimal Winn session identity. `reason` is `none`
except on `aborted`, where it MUST be a member of the closed enum
`carrier_rate_limited`, `invalid_carrier_mtu`, `response_auth_failed`,
`awg_backend_unavailable`, `audit_unavailable`. A verifier MUST reject an
unrecognised schema token, class, mode, or abort reason rather than accept an
event it cannot classify; extending the enum requires a new schema version.

Redemption is followed by exactly one `<carrier>_authenticated` record, then by
exactly one mutually exclusive terminal record of class `auth_only`, `open`, or
`aborted`. Every rejection path after redemption MUST emit the `aborted` class
before answering the peer. An `open` request MUST additionally record exactly
one `closed`. A terminal class is claimed only once its record is durable, so a
rejected write leaves the request free to seal its real terminal class.

Sealed evidence MUST reconcile exactly, per carrier:

```
authenticated == auth_only + open + aborted
open          == closed
```

and, across all carriers sharing one redemption store:

```
durable redemptions == authenticated records whose mode is anonymous-token
```

An offline verifier MUST recompute these counts from manifest-bound evidence
rather than trust the producing harness, and MUST reject a missing terminal
event, a duplicate terminal event for one correlation identity, an unknown
abort reason, a terminal event whose event name and declared class disagree,
and any terminal event with an absent or uncorrelated correlation identity. The
redemption snapshot used by the equation MUST itself be covered by the evidence
manifest and, where anchoring applies, by the anchor commitment.

If the audit sink refuses the `authenticated` record or a terminal record, the
request contributes to one side of the equation and not the other, the
reconciliation fails, and the run is invalid. This is the intended outcome: a
redemption that cannot be accounted for MUST invalidate the evidence rather
than be quietly absorbed.

## 10. Mobility and carrier extension

The carrier authorization contract is version `3`, the carrier envelope magic
is `WCF2`, and the complete behavior is specified in
`MOBILITY_AND_CARRIER.md`.

### 10.1 Trusted deployment

Outside explicit lab mode, both endpoints MUST verify:

- an unexpired `winn-gateway-manifest/v1` document, valid for no more than
  seven days and signed by a pinned controller ML-DSA key;
- the manifest's inclusion in the complete signed append-only transparency
  receipt chain; and
- an externally retained checkpoint that is not ahead of or inconsistent with
  that chain.

The manifest binds its monotonic sequence, previous digest, controller, suite,
minimum client, node endpoint/TLS name, IP hints, ECHConfigList, maximum inner
datagram, authorization modes, and any privacy-token verification keys. Direct
endpoint inputs MUST NOT override a verified manifest.

### 10.2 Carrier authorization

Every carrier MUST use TLS 1.3, exactly the manifest-selected hybrid group,
mandatory ECH, ALPN `h3` or `h2`, a fresh handshake, and no 0-RTT.

The selected node MUST explicitly authorize exactly one of:

- `identity`: mutual P-384 X.509 authentication plus a registered device
  ML-DSA request signature;
- `anonymous-token`: no stable client certificate, a one-time RFC 9474
  RSA-blind-signature token, and an ML-DSA signature made by the fresh
  ephemeral key committed into the token.

The issuer endpoint is separately operated. Issuance MUST use hybrid mTLS,
mandatory ECH, a registered device ML-DSA authorization over the blinded
request digest, timestamp, and nonce. A carrier MUST possess only the public
redemption key and MUST NOT receive issuer identity logs or the private RSA
key. A token serial MUST be consumed at most once.

Every carrier request and response MUST bind authorization mode, manifest
digest, method, authority, request target, carrier, device or token pseudonym,
session, sequence epoch, public target, timestamp, nonce, suite, maximum inner
datagram, privacy profile, request purpose, algorithm, and key ID. Stale
timestamps and repeated nonces MUST fail with bounded replay state.

HTTP/3 accepts two signed purposes. `data` allocates the fixed AWG backend and
enters the CONNECT-UDP relay. `authenticate-only` is restricted to preparation:
after verifying and consuming the one-time credential, the carrier records the
redemption boundary, signs the response, records the `auth_only` terminal class
per section 9.1, and returns without allocating a backend socket. The client MUST use a new `data` credential at click time and MUST still
pass the full envelope-MTU, inner-AWG, protected-DNS, and canary predicates.
Unsigned, unknown, or response-mismatched purposes fail closed. This
server-terminated preparation exchange prevents lossy QUIC connection-close
delivery from retaining a dead preparatory relay.

The click binding expiry authorizes only candidate construction, verification,
and commit inside the non-resettable connection deadline. It is not a live
session lifetime. After a successful commit, the H3 connection and its
protected underlay remain valid only until the separately frozen earliest
trusted expiry covering the descriptor, manifest, PSK generation, anonymous
credential lease, and underlay authorization. Post-commit operations MUST use
the exact original binding, MUST NOT create a new candidate from an expired
binding, and MUST fail closed at that independent session-trust expiry.

### 10.3 Transport and continuity

HTTP/3 uses RFC 9298 CONNECT-UDP and RFC 9221 QUIC DATAGRAM. A client MAY
migrate a live QUIC connection to a replacement bound UDP socket only after
RFC 9000 path validation succeeds. The old path MUST remain active on failed
validation.

The HTTP/2 fallback uses `POST /winn/v2/udp-stream` with media type
`application/vnd.winn.udp-stream;version=2`. Both carriers encapsulate every
inner datagram in a bounded WCF2 envelope carrying type, sequence number,
logical length, and optional padding; H2 additionally prefixes that envelope
with a two-byte unsigned network-order length.

A conforming implementation:

- MUST preserve the Winn session ID, sequence epoch, AWG keys/interface, and
  current generation when changing only underlay, carrier type, or node;
- MUST use one monotonic data sequence across old and new carriers;
- MAY duplicate data during handoff for at most one second and 128 datagrams,
  using the identical sequence so the server delivers one copy;
- MUST NOT claim simultaneous multipath QUIC from this bounded redundancy;
- MUST connect only to the configured AWG UDP backend;
- MUST limit an inner datagram to at most 1,500 bytes and MUST NOT truncate;
- MUST cancel every losing candidate after one winner proves all online
  predicates and give every materialized or late loser one persistent,
  idempotent teardown owner;
- MUST permit no losing candidate to install global routes or DNS. Therefore a
  verified winner may commit before isolated loser process cleanup completes;
  loser cleanup continues to proven postconditions without extending or
  resetting the three-second connect deadline;
- SHOULD perform authenticated inner-MTU probing and react to QUIC
  `DatagramTooLarge` signals;
- SHOULD race IPv6 and IPv4 candidates and MAY use signed address hints or a
  configured DNS64/NAT64 prefix;
- MUST remain fail closed until replacement TLS and application
  authentication finish.

The optional high-risk profile MAY add bounded bucket padding, jittered
keepalives, and explicitly enabled cover frames. Cover frames MUST never be
delivered to AWG and MUST remain bounded to avoid uncontrolled battery or
metered-data use.

## 11. Non-applicability to standalone v3 (added 2026-08-12 — audit, no code change)

Sections 2–10 above are **v2-only**. The following v3 facts are not specified here and MUST NOT be inferred from this file:

- **Handshake / transport magic:** v3 transport is `DemuxToken (8) || AEAD(frames+padding)` with `TransportOverhead()=26` and `Overhead()=29` (`tun.Overhead() = 29; InnerMTU = MessageSize - 29; MinInnerMTUv4=576, IPv6MinLinkMTU=1280`), not WCF2. v3 handshake is `AdmissionTag (32) || whitened(ephemeral||sealed-static||sealed-payload)` (HMAC-SHA256 tag, X25519, ChaCha20Poly1305, optional Elligator2), not TLS 1.3 / X.509 / ML-KEM / ML-DSA-per-rekey. Gateway datapath never answers an unauthenticated datagram.
- **Descriptor resolver:** The gateway datapath descriptor resolver is not in this file. It is the cross-host derivation in `winn3/conform`: `GatewayID` is raw operator bytes (not base64-decoded), `AdmissionKey` is file bytes trimmed only `\r\n` (not hex-decoded), `pathMTU` default is `carrier.DefaultPathMTU=1450` (not 1280), plan floor is `carrier.Floor(pathMTU, classes...)` over every class the session may migrate to, `inner_resolver_v4` is off ML-DSA-65-signed descriptor beside `inner_router_v4` and is consumed only through the five-clause `WinsWinn3Resolvers` derivation with the narrow next-hop exception (`if advertised.isEmpty || ipv4Value(advertised) != candidate`), replacing not joining the list. The resolver is staged off by `kWinn3DescriptorFormatVersion=2` in `lib/winn_protocol_dispatch.dart`. See `winn3/conform:StandaloneMobileResolverGuards` / `StandaloneResolverGuards` / `StandaloneEnforceRoutesGuards` for needle-pinned guards (file+Needle+Why) — this file's §10.1–10.3 MUST NOT be cited for resolver behaviour.
- **Path-MTU negotiation:** `winn3/session/pathmtu.go` magic `W3PM` v1 7-byte notice (`pathMTUNoticeSize=7`) + optional 9-byte floor suffix, `NegotiatedPathMTU = min(local,peer)`, `ShrinkToPeerPathMTU` / `ClampInnerMTU`, dead zone 1280–1420 threshold 1421 (plan-aware). Gateway emits `notice []byte` via `gateway.New(cfg, pathMTU, resp, bind)` and initiator refuses via `session.Driver.refusePathMTUMismatch` / `HandhakeFailure` taxonomy. This is not §10's inner-MTU probing.
- **Manifest:** v2 control-plane manifest here is `winn-gateway-manifest/v1` (7-day). Standalone v3 uses `winn-gateway-manifest/v2` (`FormatV2`) with typed transports/circuits/regional policies. Do not derive v3 descriptor fields from v1.
- **Audit:** v3 datapath audit is per-gateway atomic counters (`handshakes/unauth/throttled/refused`) and tun stats (`RxDeviceWrites` vs `RxPackets` with `DeviceProven`), not JSONL HMAC chains. The carrier-terminal conservation equations in §9.1 do not apply to v3 datapath.
