# Client TLS fingerprint

Scope: the Winn client's **first flight** — the ClientHello a censor's DPI reads
before any Winn code has run on the far side. Addresses findings 3 and 4 of
`docs/reviews/fugu-ultra-adversarial-20260803/FINDINGS.md`.

Threat model: national-scale DPI with active probing, against users for whom
being identified as a circumvention-tool user carries physical risk.

**This document does not claim the client is unfingerprintable. It is not.**
Section 4 lists exactly what an adversary can still key on, and section 5
explains why the remaining items are structural rather than unfinished work.

Every wire value below was measured from this tree, not recalled. The
measurement harness is `internal/tlsconfig/clienthello_test.go`, which captures
the raw first flight from a configuration built through the shipped
constructors and parses it. Standard-library citations are against the
toolchain this module pins, **Go 1.26.5** (`go.mod`).

---

## 1. What changed

`internal/tlsconfig/tlsconfig.go`:

- **`ClientCurvePreferences(suite)`** — the client now offers the widest named
  group set that still key-shares the required group, instead of exactly one
  group.
- **`ValidateKeyAgreement(state, suite)`**, installed as `VerifyConnection` by
  `clientForALPN` — the negotiated group is refused mid-handshake if it is not
  the suite's group.

`internal/h3candidate/candidate.go`, `snapshotProductionDialer` — the production
H3 gate asserted `CurvePreferences == {X25519MLKEM768}` exactly. It now asserts
equality with
`tlsconfig.ClientCurvePreferences(suite)`, so the list still cannot drift in
either direction.

Nothing else changed. The server's strict profile, the cover profile, and the
post-handshake re-verification are untouched.

### The offer is not an acceptance

This is the part that must not be misread. Widening `CurvePreferences` widens
what the client *advertises*; it does not widen what the client *accepts*.

Before this change, an unwanted group was refused by `crypto/tls` itself,
because it was never advertised. Now that several are advertised, the refusal is
explicit and lives in `VerifyConnection`. That placement is deliberate:
`crypto/tls` calls `VerifyConnection` from `readServerCertificate`, which
`handshake_client_tls13.go` runs **before** `sendClientCertificate`. A server
that answers with any group but the suite's is therefore torn down *before the
client authenticates* and before any application data exists — the same point in
the handshake the old refusal occupied.

The post-handshake check the review called load-bearing
(`if state.CurveID != suite.Curve`, `tlsconfig.go`, reached via `ValidateState`
/ `ValidatePeerProfile`) is unchanged and still runs. There are now two
independent enforcement points where there was one.

`TestWidenedOfferStillRefusesAnUnwantedKeyAgreement` drives a real handshake
against a server that will only do classical X25519 — a group the client now
advertises — and fails if the handshake completes or if the client sent its
certificate first.

---

## 2. What the client puts on the wire today

Measured, ECH enabled, ALPN `h2`, suite `x25519-mlkem768`. With ECH this is the
**outer** hello: `crypto/tls` derives it from the inner hello by replacing only
the server name, the random, and the ECH extension
(`handshake_client.go`, "Split hello into inner and outer"), so every field
below is in clear text on the wire.

| Field | Value |
|---|---|
| `legacy_version` | `0x0303` |
| `session_id` | 32 bytes (TCP) / 0 bytes (QUIC, per RFC 9001 §8.4) |
| `cipher_suites` | `0x1301 0x1302 0x1303` |
| extensions, in order | `0x0000 0x0012 0xfe0d 0x0005 0x000a 0x000d 0x0032 0x0010 0x002b 0x0033` |
| `supported_groups` | `0x11ec 0x11eb 0x11ed 0x001d 0x0017 0x0018 0x0019` |
| `key_share` | `0x11ec 0x001d` |
| `supported_versions` | `0x0304` |
| `signature_algorithms` | `0x0804 0x0403 0x0807 0x0805 0x0806 0x0503 0x0603` |

On the H3 path the only difference is an empty `session_id` and
`quic_transport_parameters` (`0x0039`) inserted after `0x0012`.

### Before this change

`supported_groups` was `0x11ec` alone and `key_share` was `0x11ec` alone. A
one-element post-quantum `supported_groups` matches essentially nothing else on
the wire: it let a censor select the connection **passively**, from the first
flight, with no probing and no false-positive budget worth mentioning. That
selector is gone.

---

## 3. What that buys, stated precisely

For `x25519-mlkem768`, the outer ClientHello is now **byte-identical, in every
field measured, to that of a default-configured Go `crypto/tls` client using
ECH.** `TestClientHelloMatchesAStockGoClientWithECH` asserts this field by
field and fails if it drifts.

That is the claim. It is worth stating what it is and is not:

- **It is not browser mimicry.** The hello does not resemble Chrome or Firefox
  and cannot be made to (section 5).
- **It is a change of population.** The client no longer separates from every
  other Go TLS client on the group list. Blocking the shape now means blocking
  Go clients that use ECH.
- **That population is small.** Go TLS clients are ubiquitous in
  server-to-server traffic, but the subset that *also* uses ECH is currently
  thin, and thin cover is weak cover. As ECH deployment grows this improves on
  its own; today it should be treated as a modest gain, not a solved problem.
- **Against a determined adversary this buys little on its own.** Every item in
  section 4 remains available. The honest summary is that one cheap, reliable,
  passive selector was removed and the expensive ones were not.

### The two SecP suites cannot reach even this

`crypto/tls` key-shares only the first surviving group, so keeping a SecP hybrid
as the key share requires dropping `X25519MLKEM768` from the offer. The results
are `0x11eb 0x11ed 0x001d 0x0017 0x0018 0x0019` (P-256) and
`0x11ed 0x001d 0x0017 0x0018 0x0019` (P-384) — a post-quantum client that
*omits the only post-quantum group anything else offers*. That omission is
itself unique, so these suites remain trivially selectable.

This is not fixable downstream. `SecP256r1MLKEM768` (`0x11eb`) and
`SecP384r1MLKEM1024` (`0x11ed`) are offered by **no shipping browser**, and
BoringSSL cannot even construct them — `SSLKeyShare::Create()` has no case for
either codepoint, and Chromium's `kDefaultSSLSupportedGroups` is
`{X25519MLKEM768, X25519, secp256r1, secp384r1}`. Firefox ships
`mlkem768x25519` only; NSS defines 4587/4589 but Firefox never appends them.
There is no traffic for such a hello to hide in, at any level of effort.

**Operational consequence: deployments serving at-risk users should use
`x25519-mlkem768`.** The other two suites are appropriate for compliance-driven
deployments that need a NIST P-curve, and should be understood as
fingerprintable by construction.

The alternative — leaving `X25519MLKEM768` in the offer ahead of a SecP hybrid —
was rejected: it draws a HelloRetryRequest on every connection, and a 2-RTT
handshake is rarer on the modern web than an odd group list, so it trades a
weak signature for a louder one.

---

## 4. What an adversary can still key on

All measured. All present today.

1. **`cipher_suites` has exactly three entries.** A browser offers roughly
   sixteen, including TLS 1.2 suites and GREASE. **Not fixable in the standard
   library at all:** `crypto/tls` documents that "TLS 1.3 ciphersuites are not
   configurable" (`common.go`), and `Config.CipherSuites` is ignored for 1.3.
2. **`supported_versions` contains only `0x0304`.** Every browser also offers
   TLS 1.2. **Not fixable while ECH is mandatory:** `makeClientHello` errors
   with "MinVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is
   populated" (`handshake_client.go:176`), so a TLS 1.3-only hello is forced.
   The same constraint is what reduces `signature_algorithms` to seven entries.
3. **No GREASE anywhere** — not in cipher suites, extensions, groups, key
   shares, or versions. `crypto/tls` never emits GREASE; the only mentions in
   the package are a comment declining PSK GREASE and a server-side parser that
   skips it. Chrome emits it in five places. **Absence of GREASE is one of the
   strongest single discriminators available**, and it is unreachable from the
   standard library.
4. **Fixed extension order.** `clientHelloMsg.marshalMsg` emits a fixed order
   with no permutation hook. Chrome has permuted extension order per connection
   since Chrome 110, so even the *stability* of the order is a signal.
5. **`supported_groups` is Go's list, not a browser's.** Seven entries including
   both SecP hybrids and P-521; Chrome sends four. The `key_share` pair
   (`X25519MLKEM768` + `X25519`) does match Chrome's shape.
6. **Missing extensions browsers send:** `extended_master_secret`,
   `session_ticket`, `renegotiation_info`, `ec_point_formats` (all nil'd on the
   ECH inner hello and inherited by the outer),
   `compress_certificate`, `application_settings` (ALPS), `padding`,
   `psk_key_exchange_modes`. Chromium also now ships `trust_anchors` (`0xca34`)
   enabled by default.
7. **Behavioural signatures that no ClientHello work can touch.** Finding 1 of
   the same review — the MTU probe. Its original form was three identical
   max-size datagrams and a 300 ms retry ladder; a rewrite the same day made it
   a single jittered datagram with a transmission cap, measured at 3-6 datagrams
   over 1.26-1.94 s, **after which the connection still aborted**. That teardown
   was the sharper residual, because a censor who drops one size class *induces*
   it on demand rather than waiting to observe it.

   **This has since been closed on H3 and reduced on H2.** H3 sends no probe at
   all: the completed QUIC handshake already proves the path carries a full-size
   envelope in both directions, so the carrier reads the capacity quic-go
   established instead of demonstrating it (0 datagrams, no inducible teardown;
   dropping the envelope size class now just looks like a lossy QUIC
   connection). H2 sends exactly one datagram and still fails closed, because
   TCP gives no equivalent proof that the tunnel is wired end to end — measured
   at 1 datagram of 1,366 bytes and a closed request after 1.23-1.65 s. See
   `MOBILITY_AND_CARRIER.md` and `TestQUICHandshakeAlreadyProvesTheCarrierPath`.

   What remains on H2 is a single full-size record followed by a closed HTTP/2
   request, which is what a stalled request looks like on any HTTP client. It is
   still inducible, and it is still worth removing if the tunnel liveness it
   proves can be established another way.

`TestClientHelloDistinguishersThatRemain` asserts items 1, 2, 3 and 7 as
executable facts, so this list cannot quietly go stale.

---

## 5. uTLS: assessed, and why it is not adopted now

`refraction-networking/utls` is the known answer for ClientHello mimicry in Go.
Evidence gathered 2026-08-03 from the repository, the Go module proxy, OSV and
the Chromium/NSS sources.

### The decisive finding

**uTLS implements exactly one post-quantum group: `X25519MLKEM768`.**
`SecP256r1MLKEM768` (4587) and `SecP384r1MLKEM1024` (4589) appear **nowhere in
the repository** — not as constants, not in `isPQKeyExchange`, not in any
parrot. A custom spec cannot rescue them either: uTLS has no key-share
generation or decapsulation path for those codepoints, so advertising them
produces a hello that *fails the handshake* if the server selects the group.

For the `x25519-mlkem768` suite this is not an obstacle, because that is also
the only PQ group any browser offers. **For the two SecP suites, uTLS cannot
carry the protocol's key exchange, and no mimicry layer ever will** — as section
3 established, mimicking a browser and offering 4587/4589 are mutually
exclusive goals.

So the honest framing is not "uTLS cannot carry our PQ groups". It is: **the
only PQ group that can be mimicked is the only one uTLS supports, and Winn
already supports it.** The blocker to adoption is elsewhere.

### The actual blockers

- **uTLS is frozen at Go 1.24 `crypto/tls`.** Its last upstream sync is "merge
  changes from go 1.24.0" (2025-03-01, shipped v1.7.0); `go.mod` declares
  `go 1.24`. This module is on Go 1.26.5. Adopting uTLS means running the TLS
  client on a fork that is two Go releases behind, including behind the release
  that added the SecP hybrids — permanently forfeiting suite parity between the
  H2 and H3 paths and inheriting a separate security-fix pipeline for the most
  attack-exposed code in the tree.
- **QUIC is not one dependency, it is a stack replacement.** uTLS's own
  `QUICConn` covers the TLS layer, but Initial-packet mimicry requires
  `refraction-networking/uquic`, described by its authors as a **hard fork of
  quic-go**. It does not require quic-go; it replaces it. It tracks quic-go
  v0.59.1 against this tree's v0.60.0, its last release is v0.0.6 (2024-07-19),
  and its ML-KEM and ECH parrots exist only on unreleased master.
  **Adopting mimicry for H3 means replacing the QUIC stack**, which is a far
  larger change than adding a dependency.
- **Supply-chain cost is real and this project is about to be audited.**
  `docs/audit/06-DEPENDENCY-INVENTORY.md` records 8 direct dependencies, all
  permissive, and makes a specific claim the audit rests on: *all post-quantum
  key exchange comes from the Go standard library, not from a dependency*.
  uTLS would be the 9th direct dependency, would add ~31,000 lines of
  non-test Go, would pull in `andybalholm/brotli` and `klauspost/compress`, and
  **would move the TLS key exchange out of the standard library**, invalidating
  that claim. uquic would add more still.
- **Track record.** Three published advisories, all against uTLS itself:
  CVE-2026-26994 (ServerHellos accepted without checking TLS 1.3 downgrade
  canaries — a crypto weakness, not a cosmetic one), CVE-2026-27017 and
  CVE-2026-26995 (both fingerprint bugs that made the parrots distinguishable —
  i.e. failures of the exact property one adopts the library for).
- **Cadence and freshness.** Two releases in the last twelve months, roughly
  twelve commits to master; the newest *released* parrots are Chrome 133
  (Feb 2025) against a current stable of Chrome 151. Newer parrots exist only on
  master. Its ECH implementation carries an explicit "Unstable API: work in
  progress" warning and still cites draft-ietf-tls-esni-18 rather than RFC 9849.

### Recommendation

**Do not adopt uTLS in this cycle.** It is the right tool and it would be a real
improvement to the passive fingerprint, but adopting it today means a two-Go-
release-old TLS client, a forked QUIC stack, a broken audit claim about
standard-library-only key exchange, and a library whose own CVE history is
mimicry failures — traded against a benefit that finding 1's behavioural
signature would largely negate anyway.

**Sequence it after the behavioural findings.** Fixing the ClientHello while the
MTU probe still emitted a burst of max-size datagrams at setup would have been
optimising the quieter signal. The order that actually reduces blockability is:
finding 1 (MTU probe), finding 2 (padding defaults), then ClientHello mimicry.
Finding 1 is now closed on H3 and reduced to one datagram on H2 (see item 7
above), so the first of those three is no longer the blocker it was.

**Revisit when** uTLS syncs to a current Go `crypto/tls`, its ECH API loses the
unstable warning, and uquic reaches a release that tracks a supported quic-go —
or if a maintained alternative appears. If uTLS is adopted later, it should sit
behind a seam at `internal/tlsconfig`'s client constructors, which are already
the single place every client `tls.Config` is built.

---

## 6. Not done

- **Finding 3's residual server path.** The server half of finding 3 is closed
  for the shipped `winn-carrier-server` by the cover profile, which is applied
  unconditionally to both listeners and accepts ordinary versions and groups
  (`TestCoverProfileAcceptsOrdinaryTLSVersionsAndGroups`). The strict
  single-group profile is only reachable by a peer that presents both an ECH
  extension and the deployment's private server name. A prober holding that name
  still draws `handshake_failure` where a real origin would negotiate.
  Widening the *server's* `CurvePreferences` would not close this — it would
  move the failure from an immediate alert to a late one after the server flight
  — so it was not done. The right mitigation is denying the prober the name,
  which is what the concurrently-landed `AllowWinnLeafAsCover` requirement in
  `ApplyCoverProfile` now forces.
- **Browser mimicry.** Blocked as described above.
