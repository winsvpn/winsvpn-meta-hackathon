# Winn Protocol v2 Test Vectors

[`testvectors/v2.json`](testvectors/v2.json) contains deterministic,
language-neutral vectors for every v2 suite:

- canonical unsigned request field ordering;
- domain-separated request digest;
- next response generation;
- suite/controller/device/peer/generation/PSK-bound key identifier.

The vector request deliberately leaves `auth_signature` empty. ML-DSA
signatures are randomized, so one signature byte string is not a canonical
protocol vector. Implementations should:

1. construct the canonical message from the vector request;
2. match `request_digest`;
3. sign that message with their ML-DSA implementation and context
   `Winn-Protocol-v2`;
4. verify the signature independently;
5. match the response `key_id`.

The vector PSKs and placeholder key IDs/signatures are public test material and
MUST NOT be used in a deployment.

Run:

```sh
go test ./testvectors
```

The main test suite additionally verifies Winn ML-DSA-65 and ML-DSA-87
signatures with OpenSSL 3.6, and performs mutual-TLS handshakes between OpenSSL
and the Go controller for all three ECDHE+ML-KEM groups. Those live tests cover
standards interoperability that deterministic JSON vectors cannot.

---

# winn3 carrier key bundle (standalone identity vectors)

`winn3/conform/testdata/winn3_carrier_keybundle.json` is a **public-only**,
standalone winn3 carrier-identity key bundle. It is the reproduction target for
the `-carve` mode of `cmd/winn-carrier-keys` and for
`winn3/carrier.TestCommittedCarveFixtureMatchesDerivation`, which fails if the
committed fixture drifts from the derivation.

## What one identity is

A winn3 carrier identity is an X25519 static key — the classical
proof-of-possession key the handshake in `winn3/core/keys.go` describes. A
bundle is a set of these, one per role (for example
`gateway.wins-sea-01`, `client.wins-sea-01`), all derived from a single 32-byte
seed.

## Derivation

Every identity is derived from the 32-byte seed through HKDF-SHA256 with
per-role domain separation:

- `prk = HKDF-Extract(sha256, seed, salt = "winsvpn.winn3.carrier-keybundle")`
- per role: `scalar = HKDF-Expand(sha256, prk, role, 32)` → X25519 key pair

`kdf`, `domain`, and the seed's fingerprint
(`sha256(domain || seed)`) are recorded in the bundle's `derivation` block. The
bundle carries **public halves and fingerprints only** — deliberately no private
scalar and no seed, so a committed fixture is not a secret.

## Reproducing the committed fixture

```sh
./winn-carrier-keys -carve winn3/conform/testdata \
  -carve-seed 98037684190bcdeb1a72e276f3d914ea893f0722f6156529186aa1246dfbe13f \
  -carve-roles gateway.wins-sea-01,client.wins-sea-01,gateway.wins-sea-02,client.wins-sea-02 \
  -carve-check
```

The seed above is **test-only material** — anyone who holds it can re-derive the
fixture's private halves, which is the point of a reproducible vector and exactly
why it must never be reused off the bench. A fresh (non-deterministic) fixture is
produced by omitting `-carve-seed`; the seed is never printed by the command.
