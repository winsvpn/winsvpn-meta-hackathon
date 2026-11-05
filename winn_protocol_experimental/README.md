# Winn Protocol v3

This directory holds the standalone **Winn Protocol v3** implementation shipped
in Win's VPN (`winn3/core/`, `winn3/session/`, `winn3/gateway/`, `winn3/carrier/`,
`winn3/driver/`, `cmd/winn-datapath/`, `cmd/winn3-gateway/`):

- Standalone wire protocol, handshake, key schedule, and transport cryptography
  (`winn3/core/doc.go`) with zero dependency on AmneziaWG, WireGuard, or Xray.
- Hybrid post-quantum key agreement (`X25519` + NIST `ML-KEM-768`), `ChaCha20-Poly1305`
  AEAD transport frames, dual classical/PQ session signatures (`ECDSA P-384` / `Ed25519` +
  `ML-DSA-65`), per-gateway admission tags, and ephemeral demux tokens.
- Interchangeable outer carriers (`HTTP/2`, `HTTP/3`, and `MASQUE` with RFC 9849
  Encrypted Client Hello) and stateful cross-gateway session migration.

This module also retains the earlier Winn v2 post-quantum rekey controller and
carrier packages for the legacy AmneziaWG/WireGuard fallback path. The sections
below document that legacy v2 controller/carrier subsystem; see `winn3/core/doc.go`
for the standalone Winn Protocol v3 specification.

## Transactional rekey safety

The controller's rekey endpoint uses a per-tunnel transaction spanning state
preparation, active AWG-key read, new-key application, durable commit, outcome
reconciliation, any safe rollback, and terminal lease release. A lost commit
acknowledgement is reconciled from authenticated durable state; ambiguous
state never authorizes rollback. A reconciliation latch prevents later HTTP
requests from mutating that tunnel until an operator compares the durable
pending record with live AWG state.

Operational logs contain closed event/detail codes and an optional
per-process keyed request correlation. Raw device IDs, request IDs,
free-form errors, PSKs, responses, and canonical encodings of the device ID
are excluded. The separately keyed tamper-evident audit sink retains its
documented identity-hash semantics.

## Security construction

Every successful rotation requires all of the following:

1. TLS 1.3 with exactly one configured ECDHE+ML-KEM named group and ALPN
   `http/1.1`, plus mandatory RFC 9849 Encrypted ClientHello (ECH); a missing
   ECH offer and classical key-exchange fallback both fail closed.
2. A valid P-384 X.509 device certificate whose URI SAN binds the Winn device
   identity.
3. A valid device ML-DSA signature from the controller's registered key.
4. A controller ML-DSA response signature from a key pinned by the device.
5. A fresh non-zero 32-byte AWG PSK, bound to the controller, suite, device,
   peer, request, nonce, and monotonic generation.

Production carrier establishment first verifies an expiry-bounded,
ML-DSA-signed gateway manifest, its append-only signed transparency receipt
chain, an externally retained checkpoint, and mandatory ECH. A carrier uses
ALPN `h3` or `h2` and one of two explicit authorization modes:

- `identity`: P-384 mTLS plus a registered device ML-DSA signature;
- `anonymous-token`: a one-time RSA blind-signature token plus proof of
  possession by the fresh ephemeral ML-DSA key committed into that token. No
  stable device certificate is sent to the carrier.

The split token issuer authenticates the device but sees only a blinded token
request; the carrier sees the unblinded one-time token but not the enrollment
identity. Each carrier response remains controller-signed. The carrier connects
only to its configured AWG UDP backend and cannot proxy an arbitrary
destination.

The result is dual classical/PQ endpoint authentication plus hybrid
post-quantum-resistant key establishment. The supported profiles are:

| Winn suite | TLS group | Device/controller signature | Role |
|---|---|---|---|
| `x25519-mlkem768` | X25519 + ML-KEM-768 | ML-DSA-65 | Recommended default |
| `p256-mlkem768` | P-256 + ML-KEM-768 | ML-DSA-65 | NIST-curve interoperability |
| `p384-mlkem1024` | P-384 + ML-KEM-1024 | ML-DSA-87 | Larger conservative profile |

Go's `crypto/tls` implements the hybrid groups. Cloudflare CIRCL v1.6.3
implements FIPS 204 ML-DSA. The release workflow optionally signs its checksum
manifest with FIPS 205 SLH-DSA using OpenSSL, giving the slower hash-based
algorithm an appropriate offline role instead of putting it on every rekey.

## Production controls

- Encrypted, copy-on-write single-node state with an exclusive OS lock.
- Serializable PostgreSQL state for multi-controller deployments; response and
  PSK records remain AES-256-GCM encrypted inside the database.
- Exact idempotent retries, replay rejection, monotonic generations, device
  revocation, and an operator-controlled exact pending-rotation recovery.
- Per-device/IP token buckets, bounded limiter memory, and a hard concurrent
  request ceiling.
- Loopback-only health, readiness, and Prometheus metrics.
- Stable 128-bit sessions, EWMA path scoring, switch hysteresis, bounded
  backoff with cryptographic jitter, make-before-break switching, live RFC 9000
  QUIC path validation/migration, bounded handoff duplication, and fail-closed
  automatic H3-to-H2 recovery.
- RFC 9298 CONNECT-UDP over QUIC datagrams, a bounded HTTP/2 datagram framing
  fallback, IPv6-first Happy Eyeballs, DNS64/NAT64 support, adaptive inner-MTU
  probing, fixed-destination enforcement, signed response pinning, timestamp
  windows, and bounded single-use nonce/token caches.
- Signed, expiry-bounded gateway discovery with full transparency-inclusion
  verification and an externally pinned checkpoint.
- Optional high-risk privacy mode with length buckets, jittered keepalives,
  and explicitly enabled bounded cover traffic. These reduce simple traffic
  analysis; they do not make traffic invisible.
- Mandatory fsynced HMAC-chained audit records; startup verifies the full chain
  and protocol traffic fails closed if the sink becomes unhealthy.
- Overlap key sets for zero-downtime device and controller ML-DSA rotation.
- Bounded parsers, strict JSON, strict media types, no redirects, no response
  compression, private-file enforcement, and lab adapters gated by
  `-lab-mode`.
- Hardened systemd units, separate PostgreSQL migration SQL, deterministic
  builds, build metadata, dependency licenses, CycloneDX SBOM, and SHA-256
  manifests.

## Status and claims

This is an operationally hardened **production candidate**, not an independently
audited cryptographic product. The accurate claim is:

> Winn Protocol v2 uses strict hybrid ECDHE+ML-KEM TLS 1.3 and dual
> X.509+ML-DSA control-plane authentication to rotate unique AWG preshared
> keys. Its manifest-pinned, ECH-protected carrier uses either bound device
> identity or one-time blind tokens while carrying AWG datagrams across
> self-healing HTTP/3 or HTTP/2 paths.

Do not call it “quantum proof,” “unbreakable,” “invisible to DPI,” or “audited.” Production approval
for a specific service still requires the deployment owner to complete the
external items in [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md), especially
independent review, production key custody, and real platform tunnel
integration.

## Requirements

- Go 1.27 (see `go.mod`).
- OpenSSL 3.5+ for independent ML-DSA/ML-KEM interoperability tests and optional
  SLH-DSA release signatures.
- Docker for the disposable PostgreSQL release gate.
- A real `awg`, `amneziawg`, or `wg` executable for the production command
  adapter.
- `adb` plus an ARM64 USB-debugging device for the physical Android gate.

## Verification

```sh
cd winn_protocol_experimental
./scripts/verify.sh
```

That gate runs module verification, shell parsing, vet, Staticcheck, gosec,
govulncheck, the race detector, parser/signature/frame fuzzing, OpenSSL
interoperability, real HTTP/3 and HTTP/2 carrier tests, live carrier
failure/recovery and QUIC path-migration injection, signed-manifest
transparency, ECH downgrade rejection, blind-token issuance/redemption,
adaptive MTU, all three local protocol suites, byte-for-byte reproducible
builds, and real PostgreSQL transactions.

Focused tests:

```sh
./scripts/smoke.sh
./scripts/carrier_smoke.sh
./scripts/advanced_carrier_smoke.sh
./scripts/postgres_test.sh
./scripts/android_smoke.sh
./scripts/reproducible_build_test.sh
```

Build cross-platform release artifacts and a CycloneDX SBOM:

```sh
./scripts/build_release.sh /private/release/output
```

## Commands

- `winn-pki`: generate an ephemeral lab CA and PQ material. It is not a
  production CA.
- `winn-server`: serve the strict rekey endpoint and apply controller-side PSKs.
- `winn-client`: request, verify, and apply a device-side PSK.
- `winn-carrier-server`: serve authenticated fixed-backend HTTP/3 CONNECT-UDP
  and HTTP/2 carrier endpoints on the same UDP/TCP port.
- `winn-carrier-client`: expose one local UDP endpoint to AWG and maintain a
  fail-closed, self-healing carrier session selected from a verified signed
  manifest. Direct endpoint flags exist only under `-lab-mode`.
- `winn-manifest`: create, sign, verify, append, and verify transparent gateway
  manifests and checkpoints.
- `winn-token-issuer`: separately authenticate devices and blind-sign one-time
  anonymous carrier tokens.
- `winn-token`: obtain and locally finalize an unlinkable private token bundle
  from the issuer.
- `winn-admin`: snapshot/revoke state or abort one exact stuck preparation.
- `winn-audit`: verify a complete audit HMAC chain.

Run a command with `-h` for its complete flag contract. For deployment and
recovery, start with [OPERATIONS.md](OPERATIONS.md). The normative protocol is
[SPECIFICATION.md](SPECIFICATION.md); algorithm rationale and limitations are
in [ALGORITHM_PROFILES.md](ALGORITHM_PROFILES.md),
[THREAT_MODEL.md](THREAT_MODEL.md), and [SECURITY.md](SECURITY.md).
Carrier invariants and the precise meaning of seamless continuity are in
[MOBILITY_AND_CARRIER.md](MOBILITY_AND_CARRIER.md).
