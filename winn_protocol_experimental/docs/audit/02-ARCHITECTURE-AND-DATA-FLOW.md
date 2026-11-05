# Winn Protocol v3 - Architecture and Data Flow

Measured against the tree at **2026-08-03T15:21:33Z**. See
[README.md](README.md) for measurement provenance and for corrections to
earlier descriptions of this protocol.

> **Read line numbers as snapshot-relative.** Four other workstreams were
> editing this tree while this package was written, and line numbers moved
> measurably during the writing of it. **The durable anchor is the file path
> plus the symbol name.** If a cited line does not contain what this document
> says, grep for the named symbol in the named file.

---

## 1. Shape of the system in one paragraph

Winn v3 separates an **inner session** (an AmneziaWG data plane, keyed by a
rotated pre-shared key) from an **outer carrier** (the thing that moves the
inner session's datagrams across a hostile network). The carrier is
interchangeable: HTTP/3 with CONNECT-UDP, HTTP/2 with a long-lived stream, or
`direct-awg`, which sends AWG datagrams over plain UDP with no Winn framing at
all. A separate control plane, spoken over strictly-pinned mutual TLS 1.3 with
a post-quantum hybrid key exchange, issues and rotates the inner session's
pre-shared key and distributes signed gateway directories.

The three planes are worth keeping distinct while reading:

| Plane | What it does | Key packages |
|---|---|---|
| **Control** | Device enrolment, key rotation, gateway directory distribution | `internal/bootstrap`, `internal/protocol`, `internal/pqauth`, `internal/rotation`, `internal/gatewaymanifest`, `internal/state` |
| **Carrier** | Moves opaque datagrams across the network, resists blocking | `internal/carrier`, `internal/masque`, `internal/h3candidate`, `internal/echconfig`, `internal/tlsconfig`, `internal/netdial` |
| **Data** | The actual encrypted tunnel | `internal/directawg`, `internal/awg`, `datapath/`, external `amneziawg-go` |

---

## 2. Package inventory as measured

Measured at 2026-08-03T15:21:33Z.

| Metric | Value | How measured |
|---|---|---|
| Directories containing Go files | 93 | `find . -name '*.go' ! -name '._*' \| sed 's\|/[^/]*$\|\|' \| sort -u \| wc -l` |
| Packages listed on darwin/arm64, CGO=1 | 89 | `go list ./...` |
| Packages under `internal/` | 40 | `ls -1 internal/` |
| Command packages under `cmd/` | 38 | `ls -1 cmd/` |
| Non-test Go files | 330 | `find . -name '*.go' ! -name '._*' ! -name '*_test.go' \| wc -l` |
| Non-test lines of Go | 111,279 | `cat` of the above |
| Test files | 239 | |
| Test lines of Go | 85,845 | |
| Direct module dependencies | 8 | `go.mod` |
| Indirect module dependencies | 6 | `go.mod` |

**These numbers moved while this package was being written.** Ten minutes
earlier the same commands returned 92 directories, 39 `internal/` packages,
327 non-test files and 109,592 non-test lines. The delta is a new
`internal/revocation` package plus edits landing in `internal/pqauth`,
`internal/tlsconfig`, `internal/echconfig`, `internal/carrierauth`,
`internal/masque`, `datapath` and two `cmd/` packages. Re-measure against
whatever commit is handed over; do not treat a mismatch as an error in this
document.

Note the AppleDouble caveat: this working tree is on a volume that creates a
`._<name>` sidecar for every file, 26,295 of them. Every count above excludes
them. A naive `find . -name '*.go'` overcounts by 526 files, and a naive
`grep -r` produces hundreds of spurious binary matches. Any auditor tooling run
against this working tree, as opposed to a clean export, needs the
`! -name '._*'` filter.

---

## 3. The hybrid post-quantum construction

**This section corrects the most consequential misdescription of the protocol.**

### 3.1 What is actually post-quantum, and where it lives

There are two independent post-quantum properties. They come from different
places and fail differently.

**Property one: confidentiality of the control channel against a
store-now-decrypt-later adversary.** This comes from a strict hybrid TLS 1.3
key exchange. It is implemented **entirely by the Go standard library**. This
repository contains no ML-KEM arithmetic, no X25519 arithmetic, and no hybrid
combiner. What it contains is the code that *selects and enforces* the group:

```
internal/tlsconfig/tlsconfig.go, func ParseSuite
  "x25519-mlkem768" -> tls.X25519MLKEM768
  "p256-mlkem768"   -> tls.SecP256r1MLKEM768
  "p384-mlkem1024"  -> tls.SecP384r1MLKEM1024
```

So ML-KEM-768 is paired with X25519 or with NIST P-256, and ML-KEM-1024 is
paired with P-384. Verified absent from the entire tree: any import of
`crypto/mlkem`, any use of `circl/kem`, any use of `circl/hpke`, any reference
to Kyber. The one X25519 use in the repository is not the session key exchange
at all - it is the HPKE keypair inside Encrypted Client Hello
(`internal/echconfig/ech.go:7, 60, 160`), and the code comment at `ech.go:44-45`
says so explicitly.

**Property two: authentication that survives a break in one signature family.**
This *is* implemented here, and it is a genuine dual-family requirement.
Every control-plane exchange is authenticated twice, by two unrelated
primitives, and both must verify:

- **ECDSA P-384** inside X.509, enforced by `tls.RequireAndVerifyClientCert`
  (`internal/tlsconfig/tlsconfig.go:36`), against a pinned root CA pool.
- **ML-DSA-65 or ML-DSA-87** (FIPS 204), applied to the application payload
  and verified separately (`internal/pqauth/pqauth.go:323-340, 359-376`).

Suite-to-signature binding is at `internal/protocol/protocol.go:118-127`:
`x25519-mlkem768` and `p256-mlkem768` use ML-DSA-65; `p384-mlkem1024` uses
ML-DSA-87.

**There is no Ed25519 in the session protocol.** Ed25519 appears only in the
`cmd/winn-phase1-*` anchor-trust subsystem, which is a separate operational
mechanism for pinning build and deployment anchors.

### 3.2 What happens if either primitive is broken

This is the question an auditor will ask, so it is answered directly.

| Broken | Effect on the control channel | Effect on the data plane |
|---|---|---|
| **ML-KEM** (all of it) | Falls back to the classical security of the paired curve: X25519 for `x25519-mlkem768`, P-256 for `p256-mlkem768`, P-384 for `p384-mlkem1024`. Confidentiality holds against a classical adversary. Store-now-decrypt-later protection is lost. This is the standard hybrid property and it is provided by Go's implementation, not ours. | The PSK travels inside this channel, so the PSK's forward secrecy degrades identically. |
| **X25519 or the paired NIST curve** | Falls back to ML-KEM's security. Confidentiality holds against both classical and quantum adversaries. | Same. |
| **Both** | Total loss of control-channel confidentiality. The PSK is disclosed to a passive observer, because the PSK is not independently encrypted. See section 3.4. | Data plane compromised for every generation whose PSK was observed. |
| **ECDSA P-384** | Authentication does **not** fail. The ML-DSA signature over the payload is verified independently against a pinned key, so a forged certificate alone does not yield a forged rekey response. | No direct effect. |
| **ML-DSA** | Authentication does **not** fail. Mutual TLS with a pinned CA still gates the connection. | No direct effect. |
| **Both signature families** | Full impersonation of controller or device. | An attacker can issue arbitrary PSKs. |

The signature design is deliberately AND rather than OR: both must verify, so
an attacker must break both families. The key-exchange design is the standard
hybrid OR: either surviving primitive preserves confidentiality.

### 3.3 Hashing and key derivation, precisely

**There is no SHA-3 and no SHAKE anywhere in the tree.** Grep for `sha3`,
`shake128`, `shake256` returns zero hits in Go source.

**There is no HKDF in production code.** The single `golang.org/x/crypto/hkdf`
import in the tree is at `internal/auditcheckpoint/checkpoint_test.go:34`, in a
test.

The hash used throughout is **SHA-256**. It appears in three roles:

1. **Identifier derivation.** Public key IDs and PSK key IDs are
   domain-separated SHA-256 digests, for example
   `sha256("winn-pq-auth-key/v2\x00" || algorithm || 0x00 || publicKey)`
   at `internal/pqauth/pqauth.go:297-304`.
2. **Signing transcripts.** Request and response transcripts are a literal
   ASCII label, a `0x00` separator, then canonical JSON of the unsigned struct.
   Exact labels: `"Winn-Protocol-v2/request\x00"`
   (`internal/protocol/protocol.go:322`) and
   `"Winn-Protocol-v2/response\x00"` (`protocol.go:363`).
3. **HMAC-SHA-256** for the tamper-evident audit chain
   (`internal/audit/audit.go:268, 277`) and for log-correlation blinding
   (`internal/bootstrap/server.go:399`).

Domain separation for general signing is a `domain || 0x00 || message` prefix
built by `SignDomainMessage` (`internal/pqauth/pqauth.go:387-403`) with an
allow-list of seven domains at `pqauth.go:435-445`. Note that the ML-DSA `ctx`
parameter is the *same* fixed value `"Winn-Protocol-v2"`
(`internal/pqauth/pqauth.go:36`) for every domain, so domain separation rests
entirely on the prefix, not on the ML-DSA context. That is sound but worth an
auditor's eye.

ML-DSA signing is **randomized (hedged)**, not deterministic: the `randomized`
argument to `mldsa65.SignTo` and `mldsa87.SignTo` is the literal `true`
(`internal/pqauth/pqauth.go`, in the signer constructors).

### 3.4 Where the session secret actually comes from

The AWG pre-shared key is **not** derived from any key exchange. It is 32 bytes
read from `crypto/rand` on the controller, rejected if all-zero:

- `internal/state/state.go:530-540` (file-backed store)
- `internal/state/postgres.go:724-734` (Postgres-backed store, identical)

It is then transmitted to the device as a base64 string in the `preshared_key`
JSON field (`internal/protocol/protocol.go:77`, decoded client-side at
`protocol.go:245`). The ML-DSA response signature covers that field
(`protocol.go:336, 352`), so it is **authentic**. It is not **independently
confidential**: its secrecy is exactly the secrecy of the TLS 1.3 record layer.

Internal naming in `internal/rotation/coordinator.go:18-22` calls this the
"hybrid PSK". That refers to the transport being hybrid, not to the PSK being
a hybrid KEM output. This is flagged in
[04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md)
as a naming hazard and a design question.

Related detail worth noting: the public `key_id` is derived as a bare
`sha256(context || ... || psk)` (`internal/protocol/protocol.go:273-289`), a
direct secret-into-hash construction rather than an HMAC or KDF. Preimage
resistance makes this sound for a 32-byte uniform secret, but it is not the
conventional shape.

### 3.5 Enforcement, which is the part this repository does own

The valuable, auditable crypto work in this tree is enforcement, not
arithmetic:

- Exactly one curve is offered, on both client and server:
  `CurvePreferences: []tls.CurveID{suite.Curve}` at
  `internal/tlsconfig/tlsconfig.go:85` and `:134`. No classical-only fallback
  group exists to negotiate down to.
- `MinVersion == MaxVersion == tls.VersionTLS13` (`tlsconfig.go:83-84`).
- Session tickets disabled (`:86`, `:135`); renegotiation forbidden
  (`:87`, `:136`).
- After the handshake, the negotiated curve, version, ALPN and completeness
  are re-validated and the connection is rejected on mismatch
  (`validateState` in `internal/tlsconfig/tlsconfig.go`), called from
  `internal/bootstrap/client.go` and `internal/bootstrap/server.go`.
- `KeyLogWriter` is actively rejected in the anonymous H3 carrier path
  (`internal/carrier/h3.go:439`).

**One exception to the strictness above, landed 2026-08-03 11:20 and currently
unwired.** `tlsconfig.ApplyCoverProfile` builds a deliberately ordinary-looking
listener profile that permits **TLS 1.2**, sets no `CipherSuites` and no
`CurvePreferences`, leaves session tickets enabled, and requests no client
certificate. This is an anti-active-probing measure, not a weakening of the
Winn path: the strict config is handed out only through `GetConfigForClient`,
to a peer whose SNI matches a private server name **and** whose ClientHello
carries the Encrypted Client Hello extension. The rationale, stated in the
function's own comment, is that refusing TLS 1.2, offering an unusual cipher
list, never issuing a session ticket, or sending a `CertificateRequest` to a
stranger are each single-probe discriminators. **It has no callers anywhere in
the tree at snapshot time**, so it currently protects nothing, and the
separation between cover and strict paths is unreviewed.

---

## 4. Session establishment, end to end

### 4.1 A structural finding first

**No single production binary in this tree performs the complete sequence from
"user clicks connect" to "encrypted traffic flows."** The sequence is split:

| Concern | Implemented in | Status |
|---|---|---|
| ML-DSA rekey and PSK acquisition over mutual TLS | `cmd/winn-client/main.go` | Shipping CLI. Does not discover a gateway, does not verify a manifest, does not start an AWG session. Endpoint and peer key are raw unverified flags (`cmd/winn-client/main.go:42, 48`). |
| Manifest verification, candidate racing, AWG bring-up, traffic | `cmd/winn-auto-e2e/main_linux.go` | End-to-end harness, `//go:build linux` only. |
| Cross-platform client facade | `clientbinding/binding.go` | `TunnelSupported()` returns false on every target (`binding.go:62`); `Connect` returns `ErrTunnelUnimplemented` (`binding.go:203`). |

The package's own doc comment states this at `clientbinding/binding.go:11-23`.
An auditor should read the two sequences below as two halves of a design that
is not yet joined in one shipping artifact. This is elaborated in
[04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md).

A second structural point: `rotation.Coordinator.Rotate`, the only function
that performs the live rekey network exchange, has exactly two non-test call
sites - `internal/rotation/rotation.go:63` (reached only from
`cmd/winn-client/main.go:120`) and `cmd/winn-auto-fixture/main.go:381`. The
connect path calls only `Coordinator.Pin`
(`internal/rotation/coordinator.go:271`), which reads an already-applied PSK.
**In the assembled flow, rotation must have happened out of band beforehand.**

### 4.2 Control-plane sequence: rekey and PSK acquisition

Client side, `cmd/winn-client`:

1. Parse flags; require a controller pin from exactly one source
   (`cmd/winn-client/main.go:63-74`).
2. Resolve the suite name to a `tls.CurveID` (`internal/tlsconfig/tlsconfig.go:16-27`).
3. Load the device ML-DSA signer from a `0600` seed file
   (`internal/pqauth/pqauth.go:194`). Material present at
   `internal/pqauth/pqauth.go:199`.
4. Load the pinned controller ML-DSA verifier set
   (`internal/pqauth/pqauth.go:539`, `:203`).
5. Build the mutual-TLS client config: TLS 1.3 only, single curve, no tickets,
   no renegotiation, pinned roots (`internal/tlsconfig/tlsconfig.go:97-139`).
6. Load and install ECH; the handshake will fail closed if ECH is not accepted
   (`cmd/winn-client/main.go:105-113`, `internal/echconfig/ech.go:192-204`).
7. Build the bootstrap client. The endpoint must be an HTTPS origin with no
   path, query, fragment or credentials; redirects are forbidden; keep-alives,
   compression and HTTP/2 are disabled (`internal/bootstrap/client.go:60-117`).
8. Load durable client state with `DisallowUnknownFields`, a version pin, and
   device, peer and pending-request binding checks
   (`internal/rotation/rotation.go:68-105`).
9. Build the rekey request: fresh 32-byte `request_id` and `nonce`, then ML-DSA
   sign the canonical transcript (`internal/bootstrap/client.go:119-146`,
   signature at `:139`).
10. **Persist the pending request to disk before transmitting**, so a crash
    cannot orphan a request (`internal/rotation/coordinator.go:194-203`).
11. POST over mutual TLS (`internal/bootstrap/client.go:171`). The TLS
    handshake and client-certificate authentication happen here.
12. Re-validate the negotiated TLS profile (`:176`).
13. Read at most 32 KiB (`:179-186`), enforce a strict media type with exactly
    one parameter `version=2` (`:194-197`), decode JSON with
    `DisallowUnknownFields` and a single-object EOF check (`:198-206`).
14. Select the controller verifier **by pinned (algorithm, key-id)** and verify
    the ML-DSA response signature (`:207-213`).
15. Validate the response against the request and derive the PSK
    (`internal/protocol/protocol.go:204`).
16. Apply the PSK to the AWG peer, either by writing a `0600` file or by
    invoking `awg set <iface> peer <key> preshared-key <path>`
    (`internal/awg/applier.go:104-158`).
17. Fail closed on apply error by revoking durable state
    (`internal/rotation/coordinator.go:230-239`), then persist the applied
    generation and clear the pending request (`:241-256`).

Server side, `cmd/winn-server`, all in `internal/bootstrap/server.go`:

1. Audit-sink health gate; return 503 if the audit log is unhealthy (`:69-76`).
2. Path, method and query checks (`:77-89`).
3. Concurrency semaphore (`:95-105`).
4. TLS profile re-validation (`:106-110`).
5. Derive the device identity from the **verified** certificate chain as a
   SPIFFE URI SAN; reject ambiguity (`:111`, `internal/identity/identity.go:14-53`).
6. Rate limit per `deviceID|remoteIP` (`:117-129`).
7. Strict `Content-Type` and `Accept`; reject any `Content-Encoding` (`:130-143`).
8. Body capped at 32 KiB, `DisallowUnknownFields`, single-object (`:144-160`).
9. `protocol.ValidateRequest` (`:161`).
10. Suite and controller ID checks, and **the device ID in the signed request
    must equal the certificate identity** (`:166-178`).
11. Look up the device ML-DSA key by `(deviceID, algorithm, keyID)` in the
    registry, then verify the request signature (`:184-194`).
12. Tunnel transaction and reconciliation latch (`:196-230`), then prepare,
    generate the new PSK, apply, and commit through a three-way reconciliation
    state machine that can roll back to the previous PSK (`:240-321`).

### 4.3 Data-plane sequence: bringing up a session

This is the `cmd/winn-auto-e2e` path, Linux only.

1. Load the controller ML-DSA pin set.
2. **Verify the gateway manifest** before any of its contents are used
   (`internal/gatewaymanifest/deployment_v2.go:110`): load retained trust state,
   read the manifest size-bounded with `DisallowUnknownFields`, validate
   structure, strict-base64 decode the signature, look up the pin by
   `(AuthAlgorithm, AuthKeyID)`, verify a domain-separated ML-DSA signature over
   SHA-256 of the unsigned canonical form, then check rollback, equivocation,
   gap and predecessor digest, then check transparency inclusion.
3. Verify the signed Linux deployment profile and require it to select the same
   verified node (`internal/linuxauto/deployment_loader.go:79-99`).
4. Reserve an immutable attempt identity (attempt ID, session ID, sequence
   epoch, nonce, expiry) **before any network work**
   (`internal/linuxauto/runtime.go:110-178`).
5. Assemble the prepared generation: carrier, credentials, PSK pool, policy
   anchor (`internal/preparation/production_assembler.go`).
6. Commit trust state only after preparation succeeds
   (`internal/linuxauto/deployment_loader.go:114`).
7. Race all candidates (`internal/connectivity/coordinator.go:605-802`).
8. Per candidate, dial. **This is where the AWG session actually starts**
   (`internal/directawg/candidate.go:199-322`).
9. Verify predicates in order: fresh AWG handshake, bidirectional reachability,
   then protected DNS or tunnel canary
   (`internal/connectivity/coordinator.go:945-981`).
10. The winner commits: install routes first, then DNS and kill-switch policy,
    rolling both back if policy fails
    (`internal/directawg/linux_session.go:142-180`).
11. Traffic flows through a UDP relay goroutine between the loopback socket
    `amneziawg-go` writes to and the connected gateway socket
    (`internal/carrier/relay.go:26`).

### 4.4 What `internal/directawg` does on Linux

Entry: `NewLinuxController` (`internal/directawg/linux_constructor.go:5`,
`//go:build linux`). On non-Linux this returns `ErrLinuxControllerUnsupported`
(`linux_constructor_unsupported.go:5`).

Five external binaries are invoked, all validated at construction as absolute,
regular, executable paths (`internal/directawg/linux_controller_common.go:192-200`,
`internal/directawg/linux_policy.go:131-134`):

| Default path | Role |
|---|---|
| `/opt/winn-lab/bin/amneziawg-go` | Userspace AWG data plane |
| `/opt/winn-lab/bin/awg` | AWG configuration CLI |
| `/usr/sbin/ip` | Addresses, links, routes, rules |
| `/usr/sbin/nft` | Fail-closed firewall and kill switch |
| `/usr/bin/resolvectl` | DNS policy |

Ordered bring-up in `Prepare`
(`internal/directawg/linux_controller_common.go:255-594`), abbreviated:

1. Validate binding, loopback relay endpoint, IP-literal gateway endpoint,
   gateway public key, MTU (`:265-284`).
2. Obtain key material; require generation match, 32 bytes each, non-zero;
   SHA-256 the PSK for later refresh checks (`:286-311`). Material present at
   `internal/directawg/linux_controller_common.go:355` and `:356`.
3. Derive candidate identity, reserve inner address and listen port under
   process-local leases (`:313-339`).
4. Create a `0700` temp directory; write private key and PSK to `0600` files
   (`:340-379`).
5. Start `amneziawg-go -f <iface>` as a managed child (`:382-385`).
6. Poll `ip link show dev <iface>` until the TUN appears (`:596-627`).
7. `awg set <iface> private-key ... listen-port ... fwmark ... jc jmin jmax s1
   s2 s3 s4 h1 h2 h3 h4` - the AmneziaWG obfuscation parameters come from the
   **signed** deployment profile (`:639-663`).
8. `awg set <iface> peer <gwkey> preshared-key <path> endpoint <relay>
   allowed-ips ...` (`:679-691`).
9. **Delete both secret files immediately** (`:435-440`).
10. Verify the kernel-side listen port equals the lease (`:834-860`).
11. Read a zero baseline (`awg show ... latest-handshakes|transfer|endpoints`)
    and require zero handshake and zero counters **before** the link comes up
    (`:447-467`).
12. `ip address add`, `ip link set mtu`, `ip link set up` (`:861-887`).
13. Only now set `persistent-keepalive` (`:699-722`).
14. Route transaction with rollback (`internal/directawg/linux_route.go`).
15. Policy transaction: fail-closed nftables applied as a batch file via
    `nft -f`, plus `resolvectl` for DNS, with `resolvectl revert` on rollback
    (`internal/directawg/linux_policy.go:58-100, 401-409, 456-457, 510-519`).

**No netlink and no wgctrl.** Grep for `AF_NETLINK`, `RTM_NEW`, `wgctrl` across
`internal/` and `datapath/` returns zero hits. All link, route, firewall and
WireGuard configuration is done by executing the five binaries above and
parsing their output. The only direct kernel interaction is
`setsockopt(SO_BINDTODEVICE)` and `setsockopt(SO_MARK)` on the underlay socket,
with a mandatory `getsockopt` read-back verification
(`internal/directawg/linux_socket_linux.go:24-38`, verification at
`linux_socket_linux.go:116-140`).

Teardown is ordered and retryable: policy rollback, which engages the kill
switch and restores DNS, must succeed before route rules are removed, the
interface is deleted, and the process is stopped
(`internal/directawg/linux_session.go:197`).

---

## 5. The carrier abstraction

### 5.1 The interface

A carrier is defined by one deliberately minimal interface:

```go
// internal/carrier/manager.go:19-21
type Dialer interface {
	Dial(context.Context) (net.PacketConn, error)
}
```

That is the entire required method set. A carrier is "something that produces
a `net.PacketConn`". Everything downstream speaks `net.PacketConn`.

Seven optional capability interfaces are type-asserted off the returned
connection at runtime. A carrier that does not implement one simply loses that
capability:

| Interface | Location | Method |
|---|---|---|
| `MTUAware` | `internal/carrier/envelope.go:51-53` | `EffectiveMTU() int` |
| `MTUProber` | `envelope.go:55-57` | `ProbeMTU(context.Context) (int, error)` |
| `CoverTrafficSender` | `envelope.go:59-61` | `SendCover(int) error` |
| `SequencedWriter` | `envelope.go:63-65` | `WriteSequenced([]byte, net.Addr, uint64) (int, error)` |
| `PathMigrator` | `h3_migration.go:18-20` | `MigratePath(context.Context, net.PacketConn) error` |
| `AnonymousCredentialSource` | `authentication.go:58-60` | `NextAnonymousCredential() (AnonymousCredential, error)` |
| `AnonymousCredentialResource` | `authentication.go:36-39` | `Destroy()` |

### 5.2 Concrete carriers, measured

**Exactly two types implement `carrier.Dialer` in non-test code.**

| Carrier | Client type | Server type | File |
|---|---|---|---|
| HTTP/3 CONNECT-UDP, which **is** MASQUE | `H3Dialer` (`h3.go:392`) | `H3Server` (`h3.go:33`) | `internal/carrier/h3.go` |
| HTTP/2 stream | `H2Dialer` (`h2.go:333`) | `H2Server` (`h2.go:35`) | `internal/carrier/h2.go` |

Points that matter for scoping:

- **MASQUE is not a third carrier.** It is the same `H3Dialer`. The code says
  so at `internal/carrier/supplied_socket.go:156-160`: HTTP/3 CONNECT-UDP and
  MASQUE are the same dialer, and there is no separate MASQUE dialer in the
  module. RFC 9298 CONNECT-UDP is performed through `internal/masque` over one
  QUIC connection (`h3.go:649-666, 801-826`); the server parses the request
  with `masque.ParseProxyRequest` (`h3.go:112`).
- **`direct-awg` is not a carrier at all in the `carrier.Dialer` sense.**
  `internal/directawg/udp.go:14-19` defines `UDPDialer` with an incompatible
  signature that takes an endpoint string, so it does not satisfy
  `carrier.Dialer`. It depends on `internal/carrier` only for the relay and its
  size constants. `datapath/carrier.go:119-127` states plainly that
  direct-awg has no dialer.
- **Four carrier names exist that have no implementation:** `reality-xhttp`,
  `websocket-tls`, `native-two-hop`, `privacy-two-hop`. They appear only in the
  contract enum (`internal/connectivity/contract.go:38-41`) and are hard-refused
  with `ErrCarrierUnimplemented` at `datapath/config.go:270-275`.

### 5.3 Selection

There is **no plugin registry**. No `Register()` function and no name-to-constructor
map exists in `internal/carrier`. Selection is three static mechanisms:

1. **Runtime path selection.** `Manager` is constructed with an explicit
   `[]Candidate` slice (`internal/carrier/manager.go:23-26, 80`), indexed by
   `Candidate.Path.ID` with duplicate and nil-dialer rejection (`:102-113`).
   The actual choice is delegated to the mobility engine
   (`m.engine.Select(time.Now())` at `manager.go:346`, implemented at
   `internal/mobility/engine.go:243`, scored at `:356`, with failure cooldown at
   `:368`). `Manager.Switch` (`manager.go:222`) does make-before-break.
2. **Static socket-kind map** at `datapath/config.go:83-86`, consumed at
   `datapath/carrier.go:118`.
3. **Name enum plus mode policy** at `internal/connectivity/contract.go:34-42`,
   with `Mode.Allows(carrier)` at `:330-350`. `ModeFast` permits only
   `direct-awg`; `ModeStealth` permits only the two unimplemented stealth
   carriers.

### 5.4 Inner-session framing over a carrier

The carrier treats the inner AWG session as **opaque bytes**. It never
decrypts it and adds no MAC of its own; the server writes the decoded payload
straight to the AWG backend socket
(`internal/carrier/h3_envelope.go:114`, `internal/carrier/server_envelope.go:122`).

Framing is a 16-byte cleartext header with magic `WCF2`. Encoder at
`internal/carrier/envelope.go:400-428`, decoder at `:430-457`.

| Offset | Size | Field |
|---|---|---|
| 0-3 | 4 | Magic `"WCF2"` (`envelope.go:23`) |
| 4 | 1 | Kind: 1 data, 2 probe, 3 probe-ack, 4 cover (`:24-27`) |
| 5 | 1 | Reserved; encoder never writes it, decoder rejects non-zero (`:432`) |
| 6-7 | 2 | Payload length, big-endian uint16 (`:424`) |
| 8-15 | 8 | Sequence, big-endian uint64, must be non-zero (`:401`, `:438`) |
| 16+ | var | Payload, then zero padding to the chosen outer size |

Size constants: `envelopeHeaderSize = 16`, `CarrierEnvelopeOverhead = 16`,
`AbsoluteMaxCarrierEnvelope = 1516` (`envelope.go:16-18`);
`DefaultMaxDatagram = 1350`, `AbsoluteMaxDatagram = 1500`
(`internal/carrier/common.go:12-15`).

Optional length padding to fixed buckets
`{256, 512, 768, 1024, 1200, 1280, 1400, 1500, 1516}` is applied when the
high-risk privacy profile is active (`envelope.go:95`, `outerSize()` at
`:388-398`, server-side `privacyBucket` at `server_envelope.go:171-178`).

The sequence field is **not cryptographic**. It drives server-side duplicate
suppression with a 4096-wide window (`server_envelope.go:44-86`, width at
`:13`) and make-before-break handoff duplication (`manager.go:475-503`).

Full stacking, client to server:

- **HTTP/3 and MASQUE:** AWG datagram, then WCF2 envelope, then an RFC 9298
  CONNECT-UDP datagram with a leading context-ID-0 varint
  (`internal/masque/conn.go:120-126`), then a QUIC DATAGRAM frame, then
  TLS 1.3 inside QUIC.
- **HTTP/2:** AWG datagram, then WCF2 envelope, then **an additional 2-byte
  big-endian length prefix** (`h2.go:792-804`, read side `:771-790`), then
  HTTP/2 DATA frames on one long-lived POST body (`h2.go:494-499`), then
  TLS 1.3.
- **direct-awg:** no framing at all. `datapath/config.go:50-54` states there is
  no Winn envelope on this carrier.

**A finding worth pre-empting:** a second, richer frame format exists,
`internal/wcf3` ("Winn Carrier Frame v3", magic `WCF3`, 64-byte header,
1024-byte privacy cells, replay window, `internal/wcf3/frame.go:1-56`). Its
`Encode` and `Decode` are **not called from any production path**. Grep for
`wcf3.Encode`, `wcf3.Decode`, `wcf3.Frame` yields only
`spikes/ios_maximum_privacy/fixturegen/main.go` and the package's own tests.
Production code uses only `wcf3.Context` and `wcf3.ContextFromBinding` as a
binding-identity struct, not as wire framing. **WCF2 is on the wire; WCF3 is
not.** WCF3 nonetheless has three fuzz targets and should still be reviewed if
it is intended to ship.

### 5.5 Caller-supplied sockets

This is the mechanism that will carry Android, where `VpnService.protect(fd)`
marks the socket so the mark survives `dup(2)` and `SCM_RIGHTS`. Design
rationale at `internal/carrier/supplied_socket.go:1-38`.

**Status changed during preparation of this package.** As of 2026-08-03
10:54 local time, both carriers support it. Compile-time proof at
`internal/carrier/supplied_socket.go:161-164`:

```go
var (
	_ PacketSocketDialer = (*H3Dialer)(nil)
	_ StreamSocketDialer = (*H2Dialer)(nil)
)
```

| Carrier | Socket type | Install | Consumed at |
|---|---|---|---|
| `H3Dialer` | Unconnected `net.PacketConn` (UDP) | `UseSuppliedSocket`, `h3.go:1143-1156` | `dialH3QUIC` `h3.go:1172-1182` then `dialSuppliedQUIC` `h3_migration.go:114-141` |
| `H2Dialer` | Connected, plaintext `net.Conn` (TCP) | `UseSuppliedSocket`, `h2.go:430-443` | `transportDialContext` `h2.go:455-475` then `take` `supplied_socket.go:273-297` |

Enforcement is fail-closed with no fallback:

- **Single use.** A second dial returns `ErrSuppliedSocketConsumed`
  (`supplied_socket.go:78-82, 205-216, 273-297`). The H2 path is a one-shot
  closure specifically so `http.Transport`'s automatic re-dial *fails* rather
  than opening an unprotected replacement (`h2.go:469-474`).
- **Conflict with a custom dial hook** returns `ErrSuppliedSocketConflict`
  (`supplied_socket.go:86-89`, raised at `h3.go:1147-1149, 1176-1178` and
  `h2.go:434-436, 465-467`).
- **IP literals only** on the supplied path, to prevent a DNS leak outside the
  tunnel (`requireIPLiteralEndpoint`, `supplied_socket.go:319-335`).
- **Peer match** on the TCP socket (`matchesPeer`, `supplied_socket.go:340-359`).
- **Connected-UDP rejection**, because quic-go needs `WriteTo`
  (`supplied_socket.go:182-190`).

Not supported: `H3Server` and `H2Server` have no supplied-socket API at all;
their `DialBackend` hook selects the backend AWG socket, not the client
transport. direct-awg has nothing in `internal/carrier` - its descriptor is
adopted one layer up in `datapath` (`datapath/socket.go:33, 78`, installed at
`datapath/carrier.go:178-232`, entry point `OpenWithCarrier` at
`datapath/carrier.go:76-90`).

There is **no protector callback and no `ControlFunc` hook inside
`internal/carrier`**. The model is "host opens, host protects, host hands
over". A `ControlFunc`-based protector does exist one layer out at
`internal/h3candidate/linux_socket_linux.go:35-52`, and it is mutually
exclusive with the supplied socket.

### 5.6 Path migration

`Manager.MigrateActivePath(ctx, socket net.PacketConn)`
(`internal/carrier/manager.go:187-207`) performs RFC 9000 connection migration
onto a caller-supplied socket. It requires the active connection to implement
`PathMigrator`; only `migratableH3PacketConn` does
(`h3_migration.go:40-89`). **HTTP/2 does not support in-place migration** and
returns an error (`manager.go:196-198`).

---

## 6. Encrypted Client Hello

ECH is genuinely implemented and wired, not merely parsed, and it is enforced
fail-closed. The ECH protocol itself is executed by Go's `crypto/tls`; this
module supplies, validates and generates the config material and mandates
acceptance.

- Client wiring: `config.EncryptedClientHelloConfigList` at
  `internal/echconfig/ech.go:192`.
- Server wiring: `config.EncryptedClientHelloKeys` at `ech.go:221`, keys built
  at `:172-174`.
- **Fail-closed enforcement.** Both paths chain a `VerifyConnection` hook that
  rejects the handshake unless `state.ECHAccepted` is true
  (`ech.go:194-204` client, `:223-233` server).
- Real key and config generation: an X25519 HPKE keypair and an RFC 9849
  ECHConfig (`ech.go:46-84`, marshalling at `:237-270`). `TLSKeys` cross-checks
  that each private key matches the public key in its config (`:160-170`).
- Wired at every entry point: servers at `cmd/winn-carrier-server/main.go:273-281`,
  `cmd/winn-server/main.go:179-183`, `cmd/winn-token-issuer/main.go:109-113`;
  clients at `cmd/winn-carrier-client/main.go:315-319`,
  `cmd/winn-client/main.go:105-109`, and others.
- A second, independent production gate: `internal/h3candidate/candidate.go:519-526`
  refuses any production H3 dialer whose TLS config lacks a valid ECHConfigList,
  and chains its own `ECHAccepted` check at `:531-543`.
- Interoperability is exercised by a live handshake test asserting
  `ECHAccepted` on both sides (`internal/echconfig/ech_test.go:57-58`).

**Two precise negatives an auditor should have:**

1. `internal/carrier` is itself ECH-agnostic. It never imports `echconfig`. Its
   only ECH reference is `h3.go:1226`, where the config list is hashed into the
   prepared-path profile so a warm QUIC path cannot be reused under a different
   ECH configuration. A caller that skips `echconfig.ConfigureClient` gets a
   carrier with no ECH, and `internal/carrier` will not object. The
   `h3candidate` gate is what closes this for production.
2. **ECH retry handling is absent.** Grep for `ECHRejectionError` and
   `RetryConfigList` returns zero hits tree-wide. The server marks keys
   `SendAsRetry` (`ech.go:35, 173`), but no client catches the rejection to
   re-drive the handshake with the server-supplied retry config. An ECH
   rejection surfaces as a plain handshake failure.

---

## 7. Trust boundaries with entry points

Ranked and elaborated in
[03-SECURITY-CODE-MAP.md](03-SECURITY-CODE-MAP.md). Summarised here.

| # | Boundary | Entry point | Validation |
|---|---|---|---|
| 1 | Rekey response (client) | `internal/bootstrap/client.go:171` | 32 KiB cap, strict media type, `DisallowUnknownFields`, ML-DSA verify, semantic validation |
| 2 | Rekey request (server) | `internal/bootstrap/server.go:66` | `MaxBytesReader` 32 KiB, `DisallowUnknownFields`, `ValidateRequest`, identity binding, ML-DSA verify |
| 3 | TLS peer certificate (server) | `internal/identity/identity.go:14, 21` | Requires non-empty `VerifiedChains`; exact SPIFFE scheme and host; URI round-trip equality; ambiguity rejected |
| 4 | TLS peer certificate (client) | `internal/tlsconfig/tlsconfig.go:120` | Pinned roots, TLS 1.3 only, single curve, post-handshake recheck at `:155` |
| 5 | Gateway manifest v2 | `internal/gatewaymanifest/manifest_v2.go:203` then `deployment_v2.go:110` | Full chain described in section 4.3 step 2 |
| 6 | Gateway manifest v1 | `internal/gatewaymanifest/manifest.go:137` | Same shape, v1 schema |
| 7 | Signed Linux deployment profile | `internal/directawg/linux_profile.go:132` | Bound to manifest digest, clock-skew window, ML-DSA pin verify |
| 8 | Retained trust state file | `internal/gatewaymanifest/deployment_v2.go:39` | `validateTrustStateV2` at `:198-207` |
| 9 | Client rotation state file | `internal/rotation/rotation.go:68` | 1 MiB cap, `DisallowUnknownFields`, version pin, binding checks |
| 10 | Controller state file | `internal/state/state.go:720, 736` | Envelope JSON, AES-GCM open with AAD, then inner JSON |
| 11 | Datapath config JSON | `datapath/config.go:220` | `DisallowUnknownFields`, `decoder.More()` rejection, contract-version pin, endpoint literal check |
| 12 | Duplex frames (host to subprocess) | `datapath/duplex/duplex.go:275, 289` | Magic, version, reserved-must-be-zero, opcode and direction, `MaxPayload`; every error terminal and latched |
| 13 | Unix control socket and `SCM_RIGHTS` fd passing | `cmd/winn-datapath/receivefd_unix.go:61-77` | Requires exactly one `SCM_RIGHTS`; descriptor consumed at most once |
| 14 | C ABI (iOS and desktop FFI) | `cdatapath/winn_datapath.go:123, 151, 175` | NULL checks, `unsafe.Slice` with length rejection |
| 15 | Raw gateway UDP | `datapath/engine.go:384` | Oversize drop, **off-path sender filter** at `:425`, bounded queue with oldest-drop and zeroing |
| 16 | Raw AWG datagrams (relay) | `internal/carrier/relay.go:26` | `MaxDatagram`, `ExpectedLocalPeer` pinning, idle timeout |
| 17 | Carrier HTTP request claims | `internal/carrierauth/auth.go:207, 269` | Header extraction, claim validation, timestamp parse, replay ledger |
| 18 | Carrier HTTP response claims | `internal/carrierauth/auth.go:374` | Response claim validation |
| 19 | Subprocess stdout, AWG status | `internal/directawg/status_cli.go:63, 130` | Field name restricted to a 3-item allow-list, 1 MiB stdout cap, 64 KiB stderr cap |
| 20 | Subprocess stdout, generic | `internal/directawg/linux_exec.go:19` | Bounded buffers, overflow is an error |
| 21 | Subprocess stdout, `nft`/`ip` underlay | `internal/preparation/linux_underlay_runner_linux.go:55` | 2-entry path allow-list, bounded buffers |
| 22 | Subprocess stdout, `awg` PSK readback | `internal/awg/applier.go:165` | Field-count check, exact peer-key match, duplicate-peer rejection, strict base64, 32-byte non-zero |
| 23 | Subprocess stdout, nft policy health | `internal/directawg/linux_policy.go:628` | **`strings.Contains` substring match, not a structural parse** |
| 24 | Command-line arguments | `flag` in each `cmd/` | Required-flag loops, loopback enforcement, lab-mode gating |
| 25 | Environment variables | **Not a boundary** | Exhaustive grep for `os.Getenv` and `os.LookupEnv` in non-test code returns **zero** hits. `os.Environ()` appears only as a value passed into subprocess construction. `cmd/winn-phase1-soak-controller/config.go:68, 235` documents that the environment is never consulted for configuration. |
| 26 | PEM, key, registry and pin files | `internal/securefile/securefile.go:266, 339` | Size caps, permission checks, descriptor-stability re-check |

---

## 8. Key material lifecycle

### 8.1 Generation and storage

All private writes go through `securefile.AtomicWrite`
(`internal/securefile/securefile.go:14`): temp file in the destination
directory, `Chmod`, fsync, rename, then fsync the parent directory. Parent
directories are forced to `0700` by `EnsurePrivateDirectory` (`:353-381`).

**Every private artifact is `0600`. Every public artifact is `0644`. No
exceptions were found.**

| Material | Generated | Written | Mode |
|---|---|---|---|
| CA, server, device ECDSA P-384 keys | `internal/pki/pki.go:75, 95, 117` | `pki.go:310-317` | 0600 |
| State key (32 B, AES-256) | `pki.go:184-187` | `pki.go:188` | 0600 |
| Audit key (32 B, HMAC) | `pki.go:193-196` | `pki.go:197` | 0600 |
| ML-DSA seeds, 4 of them | `internal/pqauth/pqauth.go:102-108` via `pki.go:285` | `pki.go:294` | 0600 |
| ECH X25519 server keys | `internal/echconfig/ech.go:60` via `pki.go:242` | `pki.go:257` | 0600 |
| Privacy-token RSA-3072 issuer key | `internal/privacytoken/token.go:116` via `pki.go:262` | `pki.go:270` | 0600 |
| AWG PSK, controller side | `internal/state/state.go:530-533` | Inside the AES-GCM state blob, `state.go:930` | 0600 |
| AWG PSK, client applied file | `internal/awg/applier.go:69` | `applier.go:74` | 0600 |
| Client rotation state | | `internal/rotation/rotation.go:125` | 0600 |
| Audit log | | `internal/audit/audit.go:92, 102` | 0600 |

### 8.2 Reading

`securefile.OpenPrivateLimited` (`securefile.go:280-337`) is TOCTOU-resistant:
`Lstat`, regular-file check, **reject any group or other permission bit**
(`perm & 0o077 != 0` at `:291`), open, `fstat`, `os.SameFile` re-check
(`:308`), re-check permissions on the descriptor (`:312`), then a size-limited
read.

**Caveat, and it is a real one.** On Unix the ownership-verification hooks are
no-ops: `validatePrivatePath`, `securePrivatePath` and
`validateOpenedPrivateFile` all `return nil`
(`internal/securefile/permissions_unix.go:7, 11, 13`). Real ownership and ACL
verification exists only on Windows
(`internal/securefile/permissions_windows.go:14, 44, 69`). On Unix the only
control is the mode-bit check. A `0600` file owned by a different user in a
writable directory passes.

### 8.3 Zeroization

Zeroization is thorough, using Go's builtin `clear()` at roughly 200 call
sites. Representative: seeds at `pqauth.go:116, 199` and `pki.go:289`;
signatures at `pqauth.go:127, 146, 319, 331, 355, 367`; AEAD keys at
`state.go:260, 266, 711` and `credential_vault.go:210, 217, 223`; PSKs
throughout `internal/rotation/coordinator.go` and `internal/state/`.

`Signer.Destroy()` (`pqauth.go:244-262`) is mutex-serialized and idempotent: it
zeroes the circl private key by struct assignment (`:133`, `:151`), clears the
public key, and nils the closures. `sign()` refuses after destruction
(`:279-281`).

**Inherent caveat, not a defect of this code:** `clear()` on a Go slice is not
guaranteed against compiler elision, the GC may already have copied heap
values, and circl's `NewKeyFromSeed` produces internal expansions that may
persist. There is **no `mlock` and no `madvise(MADV_DONTDUMP)` anywhere in the
tree**. This is best-effort zeroization, and should be described that way to
users.

### 8.4 Logging

No key material is logged anywhere. Verified: zero matches for logging of PSKs,
seeds, private keys or secrets in non-test `internal/` or `cmd/` code.
`tls.Config.KeyLogWriter` is never set in production; its only production
appearance is a **refusal** at `internal/carrier/h3.go:439`. No `SSLKEYLOGFILE`
handling exists. Operational logs are deliberately blinded: a per-process
random key HMACs the request ID before emission
(`internal/bootstrap/server.go:387-401`).

### 8.5 Committed secrets

No PEM private key block exists anywhere in the tree. No `.key`, `.seed` or
`-key.pem` files exist. `config/` contains only network impairment profiles;
`schema/` contains only SQL.

Three PSK-shaped values are committed as conformance test vectors. Recorded per
instruction as location only:

- Material present at `testvectors/v2.json:28`
- Material present at `testvectors/v2.json:55`
- Material present at `testvectors/v2.json:82`

Each is a 44-character base64 string decoding to 32 bytes, consumed only as
input to `protocol.KeyID` at `testvectors/vectors_test.go:49-63` and cleared
after use (`:58`). Risk is assessed as low, but **UNVERIFIED:** nothing in the
tree documents them as synthetically generated, and this directory is not a git
repository, so no history scan was possible. An auditor with upstream repository
access should confirm they were never issued to a live peer and should run a
history scan for previously-committed secrets.
