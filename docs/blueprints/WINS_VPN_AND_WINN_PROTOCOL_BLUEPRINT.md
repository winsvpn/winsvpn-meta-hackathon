# Win's VPN and Winn Protocol v3: Blueprint

**Repository:** `source/wins_vpn`
**Application identifier:** `org.winsvpn.app`
**Protocol tree:** `winn_protocol_experimental/` (Go module `winsvpn.local/winnprotocol`)
**Written:** 2026-08-03
**Audience:** whoever picks this project up next (human or model), and an external security auditor.

This document answers "what is this, and why is it shaped this way". It does not
answer "what is done". For that read the companion
[WINS_VPN_AND_WINN_PROTOCOL_IMPLEMENTATION_PLAN.md](WINS_VPN_AND_WINN_PROTOCOL_IMPLEMENTATION_PLAN.md),
which is deliberately blunt about the gaps.

## 0. How to read this, and what it is not

An audit-readiness package already exists at
`winn_protocol_experimental/docs/audit/` (8 documents, written 2026-08-03 for
outreach to OTF and OSTIF). That package is the authority on measured facts
about the Go tree. This blueprint does not duplicate it. It supplies the layer
the audit package deliberately leaves out: the product boundary, the reasons
behind the design decisions, and the relationship between the shipping
application and the protocol.

Everything asserted here is traceable to code, to a test result, or to a named
document. Where a claim could not be established, it says **UNVERIFIED** rather
than guessing. Two earlier briefs in this project asserted repository paths that
did not exist, and one search scoped to `lib|android|ios` missed a real
dependency living under `packages/`. Verify again before relying on anything
below.

**One path correction, load-bearing.** The Fugu Ultra adversarial review is at
`source/wins_vpn/docs/reviews/fugu-ultra-adversarial-20260803/FINDINGS.md`.
It is **not** under `winn_protocol_experimental/docs/reviews/`, which contains
only `fuzz-hardening-20260803/` and `server-readiness-20260803/`.

## 1. What this project is

Two artifacts live in this repository, and conflating them is the single most
common error made about it.

| Artifact | What it is | State |
|---|---|---|
| **Win's VPN**, the application | A Flutter client, `org.winsvpn.app`, version `1.0.14+29`, shipping on Android and in store review. Its tunnel today is **AmneziaWG**, with an optional Xray transport. | Shipping |
| **Winn Protocol v3** | An isolated research protocol in `winn_protocol_experimental/`. A control plane that rotates AmneziaWG pre-shared keys under post-quantum-hybrid TLS, plus a carrier plane that moves AmneziaWG datagrams across a hostile network. | Not shipping. Refused at runtime by design. |

The application does not speak Winn Protocol today. `lib/main.dart` carries an
explicit refusal of `winn/3`, guarded by
`test/winn_protocol_refusal_guard_test.dart`, and enabling it is recorded in
`WINN_PROTOCOL_PLATFORM_PLAN.md` rule 2 as a governance decision rather than an
engineering one. A client that advertises post-quantum support it cannot honour
is worse than one that refuses.

**Patent-sensitive.** `winn_protocol_experimental/` must not be pushed publicly,
demoed, or disclosed before patent-counsel approval
(`COMBINED_HANDOFF_ALL_FIVE_20260731.md:310`).

## 2. Who this protects, and what a failure costs

Win's VPN is operated by a US 501(c)(3). The user population that drives the
design is people inside Myanmar and comparable environments.

The consequence of a protocol failure in that population is not a leaked
browsing history. It is that a person is identified as a user of a circumvention
tool, which carries risk of detention, violence, and death. The founder's parent
was assassinated by the Myanmar junta in 2025
(`winn_protocol_experimental/docs/audit/01-THREAT-MODEL.md:22`).

That single fact sets the severity ordering for every design decision in this
document:

> **Detectability is the primary security property. Confidentiality is second.**

A weakness that lets a censor build a list of probable users outranks a
confidentiality weakness that requires the adversary to already know whom to
target. The asset table in `01-THREAT-MODEL.md:154-173` encodes this: asset S1,
"the fact that a user runs Winn at all", outranks S10, session traffic contents.

## 3. Threat model

The current model is `winn_protocol_experimental/docs/audit/01-THREAT-MODEL.md`
(2026-08-03). This is the summary a reader needs to understand the architecture.

**Two threat-model documents exist and they are not the same document.** The
older `winn_protocol_experimental/THREAT_MODEL.md` (2026-07-25) is titled
"Winn Protocol v2 Threat Model" and models the rekey control plane: ten adversary
classes, trust boundaries, and a residual-risk list that is worth reading in its
own right (it explicitly disclaims guaranteed censorship bypass, traffic-analysis
resistance, indistinguishability from a particular browser, and "quantum proof"
claims). The audit-package document is broader, newer, and covers the carrier
and data planes. Where they differ, the audit document is current. This
duplication should be reconciled before an engagement.

### 3.1 The primary adversary

A state or state-directed operator with control of transit networks between the
user and the outside world. Assumed capabilities (`01-THREAT-MODEL.md:41-54`):

* Passive observation and indefinite storage of all traffic on controlled links.
* Stateful deep packet inspection at line rate, including TLS record and QUIC
  header parsing.
* Fingerprinting by packet size distribution, inter-packet timing, flow
  duration, and byte-count ratios.
* **Active probing** of any endpoint a client contacted, immediately or later,
  with arbitrary crafted traffic.
* Blocking, throttling, or resetting flows by fingerprint, destination, or
  heuristic score, and enumeration of known circumvention infrastructure by IP
  and ASN.
* Operation or compulsion of a domestic CA, and man-in-the-middle of any TLS
  session that trusts the system trust store.
* Compulsion of a domestic host, ISP, or app store to hand over records or
  modify a binary.
* Control of default DNS resolvers and forged answers.
* Cross-user flow correlation.
* Device seizure after the fact.
* **Store now, decrypt later**, once a cryptographically relevant quantum
  computer exists.

Two secondary adversaries are in scope and strictly weaker: an opportunistic
hostile local network, and a seized or compelled gateway operator.

### 3.2 Explicit non-goals

These are outside the model. A report describing one of them as a vulnerability
is describing an accepted design limit. Full text at `01-THREAT-MODEL.md:80-151`.

1. **Endpoint compromise.** If the device is compromised at or above the
   client's privilege, the protocol offers nothing. Key material lives in
   process memory and transiently in `0600` files; local root reads both.
2. **Global passive end-to-end correlation.** This is a single-hop tunnel, not a
   mixnet. Cover traffic and length padding raise the cost of *local*
   statistical classification; they are not claimed to defeat a global observer.
3. **Denial of service and availability.** The answer to blocking is carrier
   diversity and reconnection, not resistance. "The censor can stop the user
   connecting" is not a protocol vulnerability here.
4. **Anonymity from the service operator at the network layer.** Gateways see
   client source IPs. Anonymous authentication decouples identity from session;
   it does not hide the user from the gateway. This is a VPN, not Tor.
5. **Application-layer metadata inside the tunnel.** Winn carries bytes.
6. **The AmneziaWG cryptographic core.** Winn does not implement WireGuard or
   AmneziaWG. On Linux the data plane is the external `amneziawg-go` executable.
   Defects in its Noise implementation are upstream's. Everything Winn does
   *around* it (configuration, key material, obfuscation parameters, fail-closed
   policy) is in scope.
7. **Physical and legal coercion.** There is no plausible deniability claim and
   no duress mode.
8. **The Go toolchain and standard library.** The hybrid post-quantum key
   exchange is Go 1.26's `crypto/tls`, not this repository. A defect there is a
   defect in Winn, but it is not one this codebase can be audited for.

### 3.3 What is deliberately not attempted

Beyond the non-goals, the design declines several things on purpose:

* **No packet cipher of its own.** `README.md:12-14` states it plainly. AWG does
  the encryption; Winn manages keys and transport.
* **No plugin registry for carriers.** There is no `Register()` function and no
  name-to-constructor map in `internal/carrier`. Selection is three static
  mechanisms (`02-ARCHITECTURE-AND-DATA-FLOW.md:480-497`). Dynamic carrier
  loading would be an attack surface for a threat model whose top asset is
  detectability.
* **No use of the system trust store, ever.** See decision D2 below.
* **No in-repository KEM arithmetic.** See decision D3.

## 4. Architecture

### 4.1 Three planes

`02-ARCHITECTURE-AND-DATA-FLOW.md:26-33`. Keep these distinct while reading any
part of the tree.

| Plane | Job | Principal packages |
|---|---|---|
| **Control** | Device enrolment, PSK rotation, signed gateway directory distribution | `internal/bootstrap`, `internal/protocol`, `internal/pqauth`, `internal/rotation`, `internal/gatewaymanifest`, `internal/state` |
| **Carrier** | Move opaque datagrams across a hostile network and resist blocking | `internal/carrier`, `internal/masque`, `internal/h3candidate`, `internal/echconfig`, `internal/tlsconfig`, `internal/netdial` |
| **Data** | The actual encrypted tunnel | `internal/directawg`, `internal/awg`, `datapath/`, external `amneziawg-go` |

The inner session (AmneziaWG, keyed by a rotated PSK) is separated from the
outer carrier (the thing that moves its datagrams). The carrier treats the inner
session as opaque bytes; it never decrypts it and adds no MAC of its own
(`02-ARCHITECTURE-AND-DATA-FLOW.md:499-504`).

### 4.2 Two version namespaces, which look like a contradiction and are not

This trips up every new reader. Both are correct:

| Constant | Value | Meaning | Location |
|---|---|---|---|
| `protocol.Version` | `winn/2` | The **rekey control-plane** wire version, specified in `SPECIFICATION.md` | `internal/protocol/protocol.go:19` |
| `connectivity.Version` | `winn/3` | The **overall protocol / datapath** version announced to hosts | `internal/connectivity/contract.go:15` |

`clientbinding` exposes both deliberately: `ProtocolVersion()` returns `winn/3`,
`RekeyProtocolVersion()` returns `winn/2` (`clientbinding/binding.go:48,52`).
The tree-root `README.md` and `SPECIFICATION.md` are both titled "Winn Protocol
v2" and describe the control plane accurately; the project is called v3 because
of the carrier and datapath layers added on top. **This is documentation drift
that an auditor will trip on and it should be reconciled before an engagement.**

### 4.3 Carriers: two dialers, plus a non-carrier

Exactly **two** types implement `carrier.Dialer` in non-test code
(`02-ARCHITECTURE-AND-DATA-FLOW.md:452-478`):

| Carrier | Client type | File |
|---|---|---|
| HTTP/3 CONNECT-UDP, **which is MASQUE** | `H3Dialer` | `internal/carrier/h3.go:392` |
| HTTP/2 long-lived stream | `H2Dialer` | `internal/carrier/h2.go:333` |

**MASQUE is not a third carrier.** It is the same `H3Dialer`, which performs
RFC 9298 CONNECT-UDP through `internal/masque` over one QUIC connection. The
code says so at `internal/carrier/supplied_socket.go:156-160`. Anyone counting
"h2, h3, masque" as three has counted one dialer twice.

**`direct-awg` is not a carrier in the `carrier.Dialer` sense at all.**
`internal/directawg/udp.go:14-19` defines `UDPDialer` with an incompatible
signature; `datapath/carrier.go:119-127` states plainly that direct-awg has no
dialer. It sends AWG datagrams over plain UDP with no Winn framing whatsoever
(`datapath/config.go:50-54`).

Four further carrier names exist in the contract enum and have **no
implementation**: `reality-xhttp`, `websocket-tls`, `native-two-hop`,
`privacy-two-hop`. They are hard-refused with `ErrCarrierUnimplemented` at
`datapath/config.go`. They appear in configuration surfaces, which makes them
look supported. They are not.

The `Dialer` interface is one method (`internal/carrier/manager.go:19-21`):

```go
type Dialer interface {
	Dial(context.Context) (net.PacketConn, error)
}
```

Seven optional capability interfaces are type-asserted off the returned
connection at runtime (`MTUAware`, `MTUProber`, `CoverTrafficSender`,
`SequencedWriter`, `PathMigrator`, `AnonymousCredentialSource`,
`AnonymousCredentialResource`). A carrier that does not implement one simply
loses that capability. That is the whole extension mechanism.

### 4.4 AmneziaWG is one carrier choice, not a foundation

`internal/directawg` is the only package under `internal/` that references
AmneziaWG, 1 of 42 as measured on 2026-08-03T16:51Z. Counting the wider tree
(`datapath/`, `cdatapath/` and nine `cmd/` harnesses) the footprint is about 14
directories (`docs/audit/README.md`). The control plane, `pqauth`, and the h2
and h3 carriers do not touch it.

`internal/awg` is a separate, small package (274 non-test lines) that applies
configuration by executing the `awg` binary. It is not an AmneziaWG
implementation either.

### 4.5 Host owns the tunnel device, Go owns the protocol

This is the contract every platform lane builds against
(`WINN_PROTOCOL_PLATFORM_PLAN.md:79-91`). It is the only shape that works on all
five platforms, and it is exactly how `libwg-go.a` already works on Apple in
this repository.

```
WinnTunnelCreate(configJson, udpFd) -> handle | error
WinnTunnelWriteInbound(handle, buf, len)      // host tun -> protocol
WinnTunnelReadOutbound(handle, buf, cap) -> n // protocol -> host tun
WinnTunnelStatusJSON(handle) -> json
WinnTunnelClose(handle)
```

Go must **never** create an OS network interface, edit routes, or shell out to
`nft`/`ip`/`awg` on a mobile or desktop host. The reason is not preference: the
existing Linux assemblies drive external binaries as subprocesses, and Android,
iOS, macOS and Windows cannot shell out to `nft`. That, not portability, is why
there is no tunnel on those platforms.

**Contract clarification that four lanes depend on**
(`WINN_PROTOCOL_PLATFORM_PLAN.md:250-274`): the frames carry **AmneziaWG outer
datagrams, not IP packets**. This Go module contains no WireGuard or AmneziaWG
implementation. The seam sits *below* AWG:

```
host tun -> host's existing AWG engine -> WINN DATAPATH -> network
```

`payload:"ip-packet"` is refused at create time rather than silently forwarding
cleartext to the gateway.

Transport of that contract per platform:

| Platform | Transport | Why |
|---|---|---|
| iOS | c-archive static library plus C header | iOS forbids subprocesses. Forced. |
| macOS | c-archive, same as iOS | Shares the Apple wrapper and framework staging. |
| Android | subprocess plus AF_UNIX socket | Matches the existing `libxray.so` precedent exactly. |
| Windows | subprocess plus anonymous duplex pipe | Matches the existing `winsvpn_awg_engine.exe` precedent. |
| Linux | either | Already has the exec carrier. Lowest priority. |

Subprocess hosts share one normative framing, `WNN3`, a 16-byte little-endian
header (magic `0x334E4E57`, version, opcode, length, reserved) defined at
`windows/runner/winn_frame.h` and mirrored by `datapath/duplex`.

### 4.6 The outer socket rule

Get this wrong and Android loops forever. The outer UDP socket must not be
routed back into the tunnel (`WINN_PROTOCOL_PLATFORM_PLAN.md:140-149`):

* **Android**: the host opens the socket, calls `VpnService.protect(fd)`, and
  hands the protected descriptor to Go over `SCM_RIGHTS` **before** the
  subprocess is spawned. Go must not open its own socket;
  `allow_own_socket` defaults to false so a missing descriptor fails loudly.
* **Apple**: `NEPacketTunnelProvider` excludes its own traffic via
  `NEIPv4Settings.excludedRoutes`, so Go may open the socket.
* **Windows**: no `VpnService.protect` exists. A `/32` host route to the peer
  endpoint is pinned on the physical interface **before** any adapter or default
  route exists; longest-prefix match then guarantees the outer socket egresses
  the physical NIC for the life of the tunnel.

## 5. Design decisions, and why

Each of these constrains the architecture. The "why" is the part that is
expensive to rediscover.

### D1. Detectability outranks confidentiality

Consequence: cover traffic, fixed-bucket length padding, carrier diversity, and
mandatory ECH are first-class, and the top question for an auditor is whether
Winn traffic can be distinguished from its cover protocol at line rate. It is
also why an unpadded or conspicuous path is treated as a release blocker rather
than a performance note.

### D2. The client never uses the system trust store

Because the adversary is assumed to operate or compel a domestic CA (capability
A7). `internal/tlsconfig` builds a TLS 1.3 configuration with a pinned
`RootCAs` pool loaded from a file (`tlsconfig.go:120`), `MinVersion ==
MaxVersion == TLS13`, a single-element `CurvePreferences`, session tickets
disabled, and renegotiation forbidden. On top of TLS, the controller's ML-DSA
public key is pinned by `(algorithm, key-id)` and every rekey response is
verified against that pin (`internal/bootstrap/client.go:207-213`). Breaking the
TLS channel is not sufficient to forge a rekey response.

### D3. Post-quantum key agreement is delegated to the Go standard library

The hybrid TLS 1.3 key exchange is implemented **entirely by Go 1.26's
`crypto/tls`**. This repository contains no ML-KEM arithmetic, no X25519
arithmetic for the session, and no hybrid combiner. What it contains is the code
that selects and enforces the group, at `internal/tlsconfig/tlsconfig.go`,
`func ParseSuite`:

```
"x25519-mlkem768" -> tls.X25519MLKEM768
"p256-mlkem768"   -> tls.SecP256r1MLKEM768
"p384-mlkem1024"  -> tls.SecP384r1MLKEM1024
```

Verified absent from the tree: any import of `crypto/mlkem`, any use of
`circl/kem`, any use of `circl/hpke`, any reference to Kyber. The one X25519 use
is the HPKE keypair inside Encrypted Client Hello
(`internal/echconfig/ech.go`), and the comment there says so.

**Why:** it narrows the crypto review surface enormously and inherits the
standard library's scrutiny. **What it costs:** a crypto reviewer auditing this
repository cannot validate the hybrid property. They can validate only that the
right group is enforced and fallbacks are refused. Whether that delegation is
the right call is an open question we want an auditor to answer
(`04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md:212-219`).

**The valuable, auditable crypto work in this tree is enforcement, not
arithmetic:** exactly one curve offered on both sides, TLS 1.3 pinned as both
minimum and maximum, tickets off, renegotiation forbidden, `KeyLogWriter`
actively rejected in the anonymous H3 path, and the negotiated curve, version,
ALPN and completeness **re-validated after the handshake** with the connection
rejected on mismatch.

The re-verification is `validateState` in `internal/tlsconfig/tlsconfig.go`
(measured at line 391 on 2026-08-03T16:51Z). The group check is three lines
(`:401-403`), and completeness is asserted separately at `:404-406` under a
`requireComplete` flag. Two entry points differ precisely in that flag:
`ValidateState` and `ValidateStateForALPN` pass `true`, and are the genuine
post-handshake path called from `internal/bootstrap/server.go`,
`internal/bootstrap/client.go`, `internal/carrier/h2.go`, `internal/carrier/h3.go`
and two `cmd/` token binaries; `ValidatePeerProfile` passes `false` because it
runs inside `tls.Config.VerifyConnection`, where the state is authenticated but
not yet marked complete.

**Cite symbols, not line numbers.** Every line number in this document is
snapshot-relative to 2026-08-03T16:51:47Z and the tree moves fast. The Fugu
review's citations, which were 34 of 34 exact when written, already no longer
resolve: it cites `tlsconfig.go:165`, which is now `:401`. If a cited line does
not contain what a document says, grep for the named symbol before concluding
the document is wrong.

### D4. Authentication is dual-family AND, not OR

Every control-plane exchange is authenticated twice by two unrelated primitives,
and **both must verify**:

* **ECDSA P-384** inside X.509, enforced by `tls.RequireAndVerifyClientCert` in
  `internal/tlsconfig`, against the pinned root pool. The keys are generated in
  `internal/pki` (`pki.go:75, 95, 117`).
* **ML-DSA-65 or ML-DSA-87** (FIPS 204, via
  `github.com/cloudflare/circl/sign/mldsa/mldsa65` and `.../mldsa87`, imported at
  `internal/pqauth/pqauth.go:17-18`), applied to the application payload and
  verified separately.

**Where the two are combined is not `internal/pqauth`.** `internal/pqauth`
contains no `crypto/ecdsa` import at all; it is the ML-DSA half only, with one
algorithm per `Verifier`. The independence property is enforced in
`internal/carrierauth/auth.go`, `RequestVerifier.Verify`: the mTLS-derived
device identity must equal the claimed device ID (`auth.go:248-250`), **and**
`pqauth.VerifyCarrierMessage` must succeed (`auth.go:277-279`). Both are hard
failures. Anyone auditing the dual-family property should start at
`carrierauth`, not at `pqauth`.

Suite-to-signature binding is at `internal/protocol/protocol.go`:
`x25519-mlkem768` and `p256-mlkem768` use ML-DSA-65; `p384-mlkem1024` uses
ML-DSA-87. ML-DSA signing is randomized (hedged), not deterministic. Domain
separation is a `domain || 0x00 || message` prefix built by
`SignDomainMessage` over an allow-list of seven domains; note that the ML-DSA
`ctx` parameter is the *same* fixed value for every domain, so separation rests
entirely on the prefix.

**There is no Ed25519 in the session protocol.** Ed25519 belongs to the phase-1
anchor-trust subsystem, a separate operational mechanism for pinning build and
deployment anchors. Stating its footprint precisely, because an earlier
description understated it: 18 non-test files reference it, 11 under
`cmd/winn-phase1-*` and 6 under `internal/` (`internal/anchorfixture`,
`internal/phase1anchor`, `internal/realcycle`). None of `internal/pqauth`,
`internal/protocol`, `internal/carrier`, `internal/carrierauth`,
`internal/tlsconfig` or `internal/bootstrap` reference it, so the substantive
claim holds: it signs nothing in the session protocol.

The asymmetry is deliberate. Signatures are AND, so an attacker must break both
families. Key exchange is the standard hybrid OR, so either surviving primitive
preserves confidentiality.

### D5. Hashing is SHA-256, and there is no HKDF in production

**There is no SHA-3 and no SHAKE anywhere in the tree.** The single
`golang.org/x/crypto/hkdf` import is in a test,
`internal/auditcheckpoint/checkpoint_test.go:34`. SHA-256 appears in three
roles: domain-separated identifier derivation, signing transcripts, and
HMAC-SHA-256 for the tamper-evident audit chain and log-correlation blinding.

(One separate hash is worth knowing about so it is not mistaken for a
contradiction: `internal/privacytoken` uses RSABSSA-SHA384-PSS-randomized blind
signatures for anonymous carrier tokens. That is a distinct mechanism, not the
session hash.)

### D6. Anonymous carrier authentication is split-issuer by construction

Two explicit authorization modes exist (`README.md`): `identity`, which is
P-384 mTLS plus a registered device ML-DSA signature; and `anonymous-token`, a
one-time RSA blind-signature token plus proof of possession by a fresh ephemeral
ML-DSA key committed into that token. The token issuer authenticates the device
but sees only a *blinded* request; the carrier sees the unblinded one-time token
but not the enrolment identity. The carrier connects only to its configured AWG
UDP backend and cannot proxy an arbitrary destination.

This buys partial unlinkability (defence D11 in the threat model). It does not
buy anonymity from the operator at the IP layer, which is non-goal 3.4.

### D7. The gateway directory is never trusted from the network

`LoadVerifiedNodeV2` (`internal/gatewaymanifest/deployment_v2.go:110`) performs,
in order: a bounded size read with `DisallowUnknownFields`, structural
validation, strict base64 signature decode, pin lookup by
`(AuthAlgorithm, AuthKeyID)`, domain-separated ML-DSA verification, then
rollback, equivocation, gap and predecessor-digest checks against retained trust
state, then a transparency inclusion proof.

This is the boundary that defends against a compelled host serving a poisoned
manifest, and it is the densest trust logic in the tree.

### D8. Everything fails closed

ECH is mandatory: the handshake is rejected unless `state.ECHAccepted` is true
(`internal/echconfig/ech.go:194-204, 223-233`), with a second independent gate
at `internal/h3candidate/candidate.go:519-543` refusing any production H3 dialer
without a valid ECHConfigList. Supplied-socket adoption is single-use, and the
H2 path is a one-shot closure specifically so `http.Transport`'s automatic
re-dial **fails** rather than silently opening an unprotected replacement
socket. Endpoints on the supplied and direct-awg paths must be IP literals, so
no name resolution escapes the tunnel. The Linux kill switch is installed as a
fail-closed nftables batch and policy rollback must succeed before routes are
torn down.

### D9. Additive only: AmneziaWG must keep working byte for byte

`WINN_PROTOCOL_PLATFORM_PLAN.md:170-171`. Winn support is added *alongside* the
shipping AmneziaWG path, never replacing it. The evidence that this held is
concrete: `ios/PacketTunnel/PacketTunnelProvider.swift` and
`macos/PacketTunnel/PacketTunnelProvider.swift` were **not modified** and remain
byte-identical to each other (md5 `20a34f265b018090311f0541b398b1b0`);
`windows_tunnel_backend.cpp`, `windows_split_tunnel.cpp`,
`windows_tunnel_service_main.cpp` and `windows_tunnel_service_protocol.h` are
unmodified; the Android manifest gained zero new permissions.

### D10. No on-switch without a governance decision

The `winn/3` refusal in `lib/main.dart` stands, and
`test/winn_protocol_refusal_guard_test.dart` fails if anyone flips it. Winn is
inert on Apple without an explicit `[winn] Enabled = true` in the tunnel config,
which nothing produces. On Windows, `WindowsConfigSelectsWinnProtocol()`
requires an explicit `[Winn] Protocol = winn/3`, which
`ValidateRestrictedTunnelConfig` rejects today and which Dart never emits.

### D11. Winn Protocol never enters `com.winsvpn.security`

`WINN_PROTOCOL_PLATFORM_PLAN.md:176-177`, stated as absolute. The reasons, as
reconstructed in
`source/wins_security/docs/20260803_winn_seam_removal_scoping/WINN_SEAM_IN_WIN_FOR_ALL_DECISION_PACKAGE.md:491-502`,
are three: keeping unreviewed post-quantum cryptography out of a shipping
antivirus binary; keeping the two products' review lineages separate so a Winn
finding does not become a Win For All finding; and preventing scope creep of the
VPN module into the AV product.

There is a fourth reason, product-level rather than code-level, and it now
dominates: **shipping a VPN inside an antivirus app makes a single installed app
evidence of circumvention use**, which is dangerous for a user in Myanmar. That
is why Win For All is removing its VPN tunnel entirely rather than integrating
this protocol. See the Win For All blueprint.

### D12. AGPL-3.0 with commercial dual-licensing

Licensing artifacts exist at the **`winn_protocol_experimental/` root**:
`LICENSE` (AGPL-3.0 verbatim, 661 lines), `COPYRIGHT`, `NOTICE`, `CLA.md`.
Before this work the project asserted no licence over its own code at all; the
only licence file in the tree was a third party's
(`07-LICENSING-AND-COPYRIGHT-FINDINGS.md:24-39`).

All 14 module dependencies are BSD-3-Clause or MIT. No GPL, AGPL, LGPL, MPL, EPL
or SSPL dependency exists.

Four things complicate the commercial half, and a CLA fixes only some of them:

1. **AI-generated authorship** is the structural one. If a meaningful share of
   the tree lacks sufficient human authorship, copyright may not subsist, so
   there is less to assign and a commercial licensee gets a weaker grant than
   expected. A CLA cannot fix this, because it assigns rights from human
   contributors and the question is whether rights exist. **Needs counsel.**
2. `internal/masque` is third-party MIT code (forked from
   `github.com/quic-go/masque-go` v0.4.0). MIT to AGPL is compatible; the notice
   obligation survives into the commercial distribution too.
3. `patches/amneziawg-go-fast-handshake-v1.patch` embeds upstream source.
4. **`amneziawg-tools`, which provides the `awg` binary Winn executes, is
   GPL-2.0**, as are `ip`, `nft`, and `resolvectl`. This constrains what any
   shipped *image* may bundle. It is a distribution exposure, not an ownership
   one, and it is a further reason to keep the separate-executable boundary
   clean and documented.

## 6. Trust boundaries

Enumerated at `01-THREAT-MODEL.md:177-251` with entry points in
`02-ARCHITECTURE-AND-DATA-FLOW.md:660-695` and ranked by exposure in
`03-SECURITY-CODE-MAP.md`.

| # | Boundary | Posture |
|---|---|---|
| B0 | Client to network | Fully hostile. Boundary zero and the reason the project exists. |
| B1 | Client to controller | Authenticated, pinned, not trusted by default. Pinned root CA pool plus an independent ML-DSA payload signature pin. |
| B2 | Client to gateway manifest | Signed, replay-resistant, rollback-resistant, transparency-checked. |
| B3 | Controller to client | Mutual TLS plus device signature. The device ID inside the signed request must equal the SPIFFE URI SAN in the verified certificate, so one device cannot rotate on behalf of another. |
| B4 | Process to operating system | **Partially trusted, and a live concern.** Winn shells out to `amneziawg-go`, `awg`, `ip`, `nft`, `resolvectl` and parses their stdout. Paths are validated as absolute regular executables; some call sites additionally enforce an allow-list and **some do not**. |
| B5 | Host application to protocol engine | Trusted caller, validated data. The caller is trusted to be the host app; the bytes it sends are still validated. |
| B6 | Disk | Trusted for integrity, not for confidentiality against local root. Private material is `0600` in `0700` directories via an atomic write path with a TOCTOU-resistant read helper. **On Unix, file ownership is never verified**; the helpers that would do so return `nil`. Real ownership and ACL verification exists only on Windows. |

## 7. Deployment targets

### 7.1 Protocol engine

Five GOOS/GOARCH tuples, declared in `scripts/build_release.sh` and mirrored in
`scripts/scanner_matrix_runner.sh`, producing 42 release binaries from 10
commands (`05-BUILD-AND-REPRODUCTION.md:60-84`):

| Tuple | Commands built |
|---|---|
| `linux/amd64` | all 10 |
| `linux/arm64` | all 10 |
| `darwin/arm64` | all 10 |
| `windows/amd64` | all 10, with `.exe` |
| `android/arm64` | `winn-client` and `winn-carrier-client` only |

Earlier statements of "9 targets" counted the same five tuples written in two
notations. Build invocation is `CGO_ENABLED=0 ... -mod=readonly -trimpath
-buildvcs=false -ldflags="-s -w -buildid="`, preceded by `go mod verify`, with a
CycloneDX SBOM and `SHA256SUMS` emitted per run.

**The CGO gap is structural and worth stating in a blueprint**, not just a plan:
because the release script and every scanner run set `CGO_ENABLED=0`, the two
packages that `import "C"` (`cdatapath`, the iOS and macOS C archive, and
`cshared`, the desktop FFI shared library) are compiled by **no automated gate
in this repository**. They are the FFI surface for the platforms that most need
one.

### 7.2 Application

Flutter client `org.winsvpn.app`, version `1.0.14+29`, with platform
directories for `android/`, `ios/`, `macos/`, `linux/`, `windows/`, `web/` and
`wear_os/`. The Android application id and namespace are declared at
`android/app/build.gradle.kts:22,38`; the Linux `APPLICATION_ID` at
`linux/CMakeLists.txt:10`; the iOS bundle at
`ios/Runner.xcodeproj/project.pbxproj:718`, with a `.PacketTunnel` extension
bundle on macOS.

The existing shipping tunnel providers, which the Winn work extends rather than
replaces:

| Platform | Provider | Lines |
|---|---|---|
| Android | `android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt` | 1382 at plan time, 1563 after additive Winn wiring |
| iOS | `ios/PacketTunnel/PacketTunnelProvider.swift` | 954 |
| macOS | `macos/PacketTunnel/PacketTunnelProvider.swift` | 954 |
| Windows | `windows/runner/windows_tunnel_backend.cpp` | 3988 |
| Apple engine wrapper | `apple/EngineWrappers/WinsAmneziaWGPacketEngine.m` | 191 |
| Windows engine | `windows/awg_engine/main.go` | 124 |

Server side: users reach Cloudflare and public aliases, then an IONOS control
hub, then data-plane VPN nodes, with an optional home core first hop for double
VPN. Deployment scripts are `server/wins_control_plane_setup_ONETOUCH.sh`,
`server/wins_data_plane_setup_ONETOUCH.sh`, `server/wins_core_server_setup_ONETOUCH.sh`.

## 8. Where the evidence lives

No key material is recorded anywhere in this document. Locations only.

| Evidence | Location |
|---|---|
| Audit readiness package (8 documents) | `winn_protocol_experimental/docs/audit/` |
| Real two-endpoint session | `~/.winn-e2e-lab/` |
| Fugu Ultra adversarial review | `source/wins_vpn/docs/reviews/fugu-ultra-adversarial-20260803/FINDINGS.md` |
| Server readiness review | `winn_protocol_experimental/docs/reviews/server-readiness-20260803/` |
| Fuzz hardening review | `winn_protocol_experimental/docs/reviews/fuzz-hardening-20260803/` |
| Platform lane plan and live progress | `WINN_PROTOCOL_PLATFORM_PLAN.md` |
| Conformance harness and baselines | `tools/winn_conformance_verify.py`, `tools/winn_conformance_results/` |
| Sealed evidence bundles (27 `.tar.gz`, not extracted) | `winn_protocol_experimental/evidence/` |
| Coordination ledger | `WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md` |
| Chronological history | `WINN_PROTOCOL_V3_CONTINUATION_LOG.md` |
| Invention record (patent-sensitive) | `WINN_PROTOCOL_V3_INVENTION_LOG.md` |

## 9. Reading order for a newcomer

1. This blueprint.
2. `winn_protocol_experimental/docs/audit/03-SECURITY-CODE-MAP.md` and section 1
   of `04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md`. Between them they say which
   of the 95 package directories are worth your time and what is already
   believed broken.
3. The companion implementation plan in this directory.
4. `WINN_PROTOCOL_PLATFORM_PLAN.md` for the platform contract and lane state.
5. `WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md` before trusting any status
   claim in an older handoff.
