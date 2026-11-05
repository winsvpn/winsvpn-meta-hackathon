# Winn Protocol v3 - Dependency Inventory

Measured against the tree at **2026-08-03T15:21:33Z**. See
[README.md](README.md) for measurement provenance.

Licence findings that affect the AGPL and dual-licensing plan are in
[07-LICENSING-AND-COPYRIGHT-FINDINGS.md](07-LICENSING-AND-COPYRIGHT-FINDINGS.md).

---

## Summary

**8 direct, 6 indirect, 14 total.** Every one is permissive: BSD-3-Clause or
MIT. **No GPL, AGPL, LGPL, MPL, EPL or SSPL dependency exists.** All 14 are
compatible with AGPL-3.0 outbound and with commercial dual-licensing.

The dependency surface is deliberately small for a 111,000-line project. The
most consequential consequence of that choice: **all post-quantum key exchange
comes from the Go standard library, not from a dependency.** See
[02](02-ARCHITECTURE-AND-DATA-FLOW.md#3-the-hybrid-post-quantum-construction).

Verification: `go mod verify` returns `all modules verified`;
`go mod tidy -diff` returns no diff.

---

## Direct dependencies

| Module | Version | Licence | Copyright holder |
|---|---|---|---|
| `github.com/cloudflare/circl` | v1.6.3 | BSD-3-Clause | Cloudflare, Inc. (2019); Google Inc. clause; **plus a nested BSD-3-Clause at `ecc/p384/LICENSE`, Brendan McMillion** |
| `github.com/dunglas/httpsfv` | v1.1.0 | BSD-3-Clause | Kevin Dunglas (2020) |
| `github.com/jackc/pgx/v5` | v5.10.0 | MIT | Jack Christensen (2013-2021) |
| `github.com/quic-go/quic-go` | v0.60.0 | MIT | The quic-go authors; Google, Inc. (2016) |
| `github.com/yosida95/uritemplate/v3` | v3.0.2 | BSD-3-Clause | Kohei Yoshida (2016) |
| `golang.org/x/crypto` | v0.53.0 | BSD-3-Clause + `PATENTS` | The Go Authors (2009) |
| `golang.org/x/net` | v0.56.0 | BSD-3-Clause + `PATENTS` | The Go Authors (2009) |
| `golang.org/x/sys` | v0.46.0 | BSD-3-Clause + `PATENTS` | The Go Authors (2009) |

### Why each is present

Import sites measured with
`grep -rn --include='*.go' '"<module>' . | grep -v '/\._'`.

#### `github.com/cloudflare/circl` v1.6.3

**Why:** post-quantum signatures and blind signatures. These are the two
primitives the Go standard library does not provide.

- **ML-DSA-65 and ML-DSA-87** (FIPS 204) in `internal/pqauth`. This is the
  post-quantum half of the dual-family authentication described in
  [02, section 3.1](02-ARCHITECTURE-AND-DATA-FLOW.md#31-what-is-actually-post-quantum-and-where-it-lives).
- **RSABSSA-SHA384-PSS-randomized blind signatures** in
  `internal/privacytoken`. This is the unlinkability mechanism behind anonymous
  carrier tokens.

**Imported by exactly 2 packages:** `internal/pqauth`, `internal/privacytoken`.

**Note for the auditor:** circl is used **only** for signatures. It provides a
KEM package; Winn does not import it. `circl/kem` and `circl/hpke` have zero
occurrences in the tree.

#### `github.com/quic-go/quic-go` v0.60.0

**Why:** QUIC and HTTP/3, which the Go standard library does not provide. This
is the transport under the HTTP/3 and MASQUE carrier, and it is what makes
RFC 9000 connection migration possible.

**Imported by 12 packages:** `internal/carrier`, `internal/masque`,
`internal/h3candidate`, `internal/netdial`, `internal/linuxauto`, `datapath`,
and 6 `cmd/` packages.

Largest and most security-relevant dependency in the tree. It sits directly on
adversary-controlled bytes.

#### `github.com/dunglas/httpsfv` v1.1.0

**Why:** RFC 9651 Structured Field Values parsing, required to read the
`Capsule-Protocol` and `Proxy-Status` headers in RFC 9298 CONNECT-UDP.

**Imported by 2 packages:** `internal/masque`, `cmd/winn-sbom-augment`.

> **Known upstream defect, worked around in-tree. Worth an auditor's attention
> because it is handled well.**
>
> `internal/masque/sfv.go` documents that httpsfv v1.1.0, the newest published
> release, **panics with an index-out-of-range** instead of returning an error
> when a Date marker `@` is the final character of a header value. The
> root cause is recorded precisely: `parseNumber` calls `isNeg`, and `isNeg`
> dereferences `s.data[s.off]` before `parseNumber` performs its `s.eof()`
> check. Reproducing values include `"@"`, `"1;a=@"` and `"a;b=@"`.
>
> Both Winn call sites feed this parser bytes a network peer controls in full:
> `ParseProxyRequest` reads `Capsule-Protocol` from an **unauthenticated**
> CONNECT-UDP request, so any client could halt a proxy goroutine; `nextHopAddr`
> reads `Proxy-Status` from a proxy response, so a hostile or tampered response
> could halt the user's client.
>
> The in-tree comment draws the right conclusion under this threat model: a
> client crash is **both a denial of service and a fingerprint**, which makes
> the client-side case the more serious of the two.
>
> The mitigation is `unmarshalItemSafely`, which recovers around the whole
> third-party parser rather than around the single known input shape, on the
> stated reasoning that the defect class is "unchecked index in a hand-written
> scanner" and one bounds check is unlikely to be the only one. It surfaces
> `ErrStructuredFieldPanic`.
>
> **Open item:** the workaround should be removed once `go.mod` requires a
> fixed release. As of the snapshot, no fixed release is required. An auditor
> should confirm the recover cannot mask a genuine logic error, and that
> `FuzzParseProxyRequest` exercises the panicking shapes.

#### `github.com/yosida95/uritemplate/v3` v3.0.2

**Why:** RFC 6570 URI Template expansion and matching, required by RFC 9298
CONNECT-UDP, whose proxy endpoint is defined as a URI template.

**Imported by 6 packages:** `internal/masque`, `internal/carrier`,
`internal/gatewaymanifest`, `internal/h3candidate`, `internal/linuxauto`,
`cmd/winn-sbom-augment`.

Relevant to security because the template match is part of parsing an
unauthenticated CONNECT request.

#### `github.com/jackc/pgx/v5` v5.10.0

**Why:** PostgreSQL driver for the optional Postgres-backed controller state
store and the single-use privacy-token redemption ledger.

**Imported by exactly 1 package:** `internal/state`.

Not on the client data path. Backend-only, and the file-backed store is the
alternative.

#### `golang.org/x/net` v0.56.0

**Why:** HTTP/2 support beyond the standard library, plus lower-level IP and
ICMP helpers used by leak detection and the Linux data path.

**Imported by 15 packages**, including `internal/carrier` (the HTTP/2 carrier),
`internal/directawg`, `internal/revocation`, `datapath`, and 11 `cmd/`
packages.

#### `golang.org/x/sys` v0.46.0

**Why:** raw syscall access. Specifically `setsockopt(SO_BINDTODEVICE)` and
`setsockopt(SO_MARK)` for underlay socket marking, file-descriptor operations
in `internal/securefile`, and platform-specific process and cgroup handling.

**Imported by 18 packages**, including `internal/securefile`,
`internal/directawg`, `internal/h3candidate`, `internal/state`, and
`internal/realcycle`.

#### `golang.org/x/crypto` v0.53.0

**Why: unclear. This is a dependency-hygiene finding.**

`golang.org/x/crypto` is declared as a **direct** requirement in `go.mod`, but
it is imported by **exactly one file in the entire tree**, and that file is a
test:

```
internal/auditcheckpoint/checkpoint_test.go:34:  "golang.org/x/crypto/hkdf"
```

There is **no production import of `golang.org/x/crypto` anywhere**. It is
carried in the release build's dependency graph and in every SBOM for the sake
of one HKDF call in one test.

**Recommendation:** either drop it, or move the test helper to a
`crypto/hkdf`-based implementation. Go 1.26's standard library provides HKDF.
This is not a vulnerability; it is unnecessary supply-chain surface, and it is
the kind of thing an auditor will flag at no benefit to anyone.

This also explains a discrepancy an auditor may notice: the project's
documentation historically described "HKDF over SHA3" as part of the protocol.
There is no HKDF in production code and no SHA-3 anywhere in the tree. See
[README, corrections](README.md#corrections-to-previously-circulated-descriptions).

---

## Indirect dependencies

| Module | Version | Licence | Pulled in by |
|---|---|---|---|
| `github.com/jackc/pgpassfile` | v1.0.0 | MIT | pgx |
| `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | MIT | pgx |
| `github.com/jackc/puddle/v2` | v2.2.2 | MIT | pgx (connection pooling) |
| `github.com/quic-go/qpack` | v0.6.0 | MIT (`LICENSE.md`), Marten Seemann (2019) | quic-go (HTTP/3 header compression) |
| `golang.org/x/sync` | v0.21.0 | BSD-3-Clause + `PATENTS` | quic-go / pgx |
| `golang.org/x/text` | v0.39.0 | BSD-3-Clause + `PATENTS` | pgx |

---

## Vendored code, which does not appear in `go.mod`

**One vendored fork exists and it must be counted as a dependency even though
`go mod` does not see it.**

### `internal/masque` - a fork of `github.com/quic-go/masque-go` v0.4.0 (MIT)

Provenance is self-documented at `internal/masque/UPSTREAM.md`:

- Upstream: `github.com/quic-go/masque-go` v0.4.0
- Source commit: `03179c5407a332f0509fa8e165244e6410ac165a`
- Annotated tag object: `0a4c589699c80369a1c4548d81d06fa9cf864a65`
- Licence: MIT, preserved at `internal/masque/LICENSE`, `Copyright 2024 Marten
  Seemann`

**Why forked rather than imported:** upstream's general-purpose `Proxy` is not
compiled, because Winn's H3 server has a fixed-target authenticated relay. The
package is carried inside the main module so that the reproducible source
manifest covers every compiled fork source file.

**Local changes**, per `UPSTREAM.md`, all correctness fixes:

- never receive from the nil `C` field of a timer created by `time.AfterFunc`
- replace a canceled read context when an expired deadline is cleared or
  extended
- generation-fence timer callbacks so a stale callback cannot cancel a newer
  deadline
- make connection close ownership idempotent, reject post-close deadline
  changes, retire deadline state under its mutex
- observe close errors in `transport.go` that upstream discarded

`conn_deadline_test.go` holds regression tests for the deadlock, context
renewal and stale-callback cases.

**These are concurrency and lifetime repairs written against upstream
behaviour rather than upstream tests, on code that parses adversary bytes.
They deserve independent review.**

The release tooling already treats this as a distinct SBOM component:
`cmd/winn-sbom-augment/main.go` emits component
`github.com/quic-go/masque-go` version `v0.4.0-winn.1` with licence `MIT` and
property `winsvpn:embedded-fork = true`, and `scripts/build_release.sh` copies
`LICENSE` and `UPSTREAM.md` into `third_party_licenses/`.

**UNVERIFIED:** no byte-level comparison against upstream was performed.
`quic-go/masque-go` is not in the local module cache, so the proportion of
surviving verbatim upstream code per file is unmeasured.

---

## Runtime dependencies that are not Go modules

These are executed as external processes on Linux and are **not** in `go.mod`.
They matter for both security review and licence compliance.

| Binary | Default path | Role | Licence |
|---|---|---|---|
| `amneziawg-go` | `/opt/winn-lab/bin/amneziawg-go` | Userspace AmneziaWG data plane | Permissive, MIT-style, per `OPERATIONS.md` |
| `awg` (amneziawg-tools) | `/opt/winn-lab/bin/awg` | AWG interface configuration | **GPL-2.0**, per `OPERATIONS.md` |
| `ip` (iproute2) | `/usr/sbin/ip` | Addresses, links, routes, rules | GPL-2.0 |
| `nft` (nftables) | `/usr/sbin/nft` | Fail-closed firewall and kill switch | GPL-2.0 |
| `resolvectl` (systemd) | `/usr/bin/resolvectl` | DNS policy | LGPL-2.1+ |

**The GPL-2.0 status of `amneziawg-tools` is a distribution constraint, not a
code-ownership problem.** No GPL code is in this tree. It constrains what may
ship inside a client, appliance or server image. `OPERATIONS.md` already flags
this and notes that invoking the tools as a separate executable is not by
itself a legal conclusion about derivative-work scope. See
[07](07-LICENSING-AND-COPYRIGHT-FINDINGS.md).

`patches/amneziawg-go-fast-handshake-v1.patch` modifies `amneziawg-go` handshake
retry timing. It embeds upstream source text as diff context. See
[07](07-LICENSING-AND-COPYRIGHT-FINDINGS.md).

---

## Toolchain dependencies of the release gate

Pinned by module hash in `scripts/scanner_matrix.sh`:

| Tool | Version |
|---|---|
| staticcheck | 2026.1 |
| gosec | v2.25.0 |
| govulncheck | v1.6.0 |
| cyclonedx-gomod | v1.10.0 (SBOM generation, `scripts/build_release.sh`) |

The gate also requires Docker and OpenSSL 3.5 or later with ML-DSA and hybrid
ML-KEM group support.

---

## Supply-chain observations

1. **`golang.org/x/crypto` is a direct dependency used only by one test.**
   Drop it or replace it with the standard library. See above.
2. **The vendored MASQUE fork is invisible to `go.mod`.** It is correctly
   handled in the SBOM tooling, but any dependency-scanning process that reads
   only `go.mod` will miss it, and will therefore also miss that Winn is
   carrying a fork of a package that parses unauthenticated network input.
3. **A known-panicking upstream parser is in the adversary-reachable path**,
   mitigated by a `recover`. Correctly handled, but it should be tracked until a
   fixed httpsfv release exists.
4. **`go mod download all` fails**, by design, under module-graph pruning. Nine
   transitive test and tool dependencies have no `go.sum` entry because they are
   never built. Use `go mod verify`.
5. **The five `PATENTS` files** accompanying the `golang.org/x/*` modules grant
   a patent licence that terminates on patent litigation against Google's Go
   implementation. Standard, not a dual-licensing blocker, but counsel should
   see it.
6. **No dependency provides post-quantum key exchange.** That comes from the Go
   standard library, so the project's most important cryptographic property is
   governed by the Go release cycle rather than by a pinned module version. An
   auditor should form a view on whether that is acceptable.
