# Winn Protocol v3 - Threat Model

Measured against the tree at 2026-08-03T15:11:39Z. See
[README.md](README.md) for measurement provenance.

This document exists to tell an auditor what counts as a finding. A threat
model that claims to defend against everything is worthless, so the non-goals
in section 3 are as important as the goals in section 2, and are stated first
in each pairing where possible.

---

## 1. Who this protects, and what failure costs

Winn Protocol v3 is the transport used by Win's VPN, a US 501(c)(3). The user
population that drives the design is people inside Myanmar and comparable
environments.

The consequence of a protocol failure in this population is not a leaked
browsing history. It is that a person is identified as a user of a
circumvention tool. In Myanmar that carries risk of detention, violence, and
death. The founder's parent was assassinated by the Myanmar junta in 2025.

This is stated because it determines how findings should be weighted. A
fingerprinting weakness that lets a censor build a list of probable users is,
for this project, more severe than a confidentiality weakness that requires the
adversary to already know who to target. **Detectability is the primary
security property. Confidentiality is second.** An auditor who finds a way to
distinguish Winn traffic from the cover protocol at line rate has found a
critical, even if no plaintext is recovered.

---

## 2. Adversary model

### 2.1 The primary adversary: a national-scale network censor

Assume a state or state-directed operator with control of the transit networks
between the user and the outside world. Specifically, assume the adversary can:

| # | Capability | Assumed |
|---|---|---|
| A1 | Passively observe all traffic on links it controls, indefinitely, and store it | Yes |
| A2 | Perform stateful deep packet inspection at line rate, including TLS record and QUIC header parsing | Yes |
| A3 | Fingerprint by packet size distribution, inter-packet timing, flow duration, and byte-count ratios | Yes |
| A4 | Actively probe any endpoint a client contacted, immediately or later, with arbitrary crafted traffic | Yes |
| A5 | Block, throttle, or reset flows by protocol fingerprint, by destination, or by heuristic score | Yes |
| A6 | Enumerate and block known VPN and circumvention infrastructure by IP and by ASN | Yes |
| A7 | Operate or compel a domestic CA, and man-in-the-middle any TLS session that trusts the system trust store | Yes |
| A8 | Compel a domestic hosting provider, ISP, or app store to hand over records or modify a binary | Yes |
| A9 | Control the DNS resolvers a client would use by default, and forge answers | Yes |
| A10 | Correlate flows across many users to identify a shared destination or a shared protocol | Yes |
| A11 | Seize a user's device after the fact and inspect on-disk state | Yes |
| A12 | Record traffic now and decrypt later, once a cryptographically relevant quantum computer exists | Yes |

Capability A12 is why the protocol is post-quantum from the start. The
population's threat is a store-now-decrypt-later archive, and the archive is
already being built.

Capability A7 is why the protocol does not use the system trust store. See
section 5.2.

### 2.2 Secondary adversary: an opportunistic local network

A hostile hotel, cafe, or mobile carrier network that performs transparent
proxying, DNS interception, or credential harvesting. This adversary is
strictly weaker than the primary and is covered by the same defences.

### 2.3 Secondary adversary: a compromised or malicious gateway operator

Win's VPN runs gateways on third-party infrastructure. Assume a gateway can be
seized or its operator compelled. The design intent is that a gateway learns
the minimum necessary and that gateway compromise does not retroactively
deanonymise past sessions. **How well that intent is met is a specific thing we
would like audited** - see
[04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md).

---

## 3. Explicit non-goals

These are outside the threat model. A report describing one of these as a
vulnerability is describing an accepted design limit, not a finding. We would
still like to know if one of them is *worse than we think*, or if a defence we
believe we have is absent.

### 3.1 Endpoint compromise

If the user's device is compromised at or above the privilege of the Winn
client, the protocol offers nothing. Malware, a hostile OS, a compromised
kernel, and a rooted or jailbroken device with a hostile actor present are all
out of scope. Key material lives in process memory and, transiently, in
`0600` files on disk; a local root can read both.

### 3.2 Global passive adversary performing end-to-end traffic correlation

An adversary that observes both the user's access link and the gateway's egress
simultaneously can correlate by timing and volume. Winn does not claim to
defeat this. It is a single-hop tunnel, not a mixnet, and it does not add
latency padding sufficient to break correlation. Cover traffic exists
(`CoverTrafficSender`, `internal/carrier/envelope.go:59`) and length padding to
fixed buckets exists (`internal/carrier/envelope.go:388-398`), but these raise
the cost of *local* statistical classification. They are not claimed to defeat
global correlation.

### 3.3 Denial of service and availability

The adversary is assumed to be able to block. Winn's answer to blocking is
carrier diversity and reconnection, not resistance. We do not claim availability
under a determined national block. Resource-exhaustion findings against a
gateway are in scope as bugs, but "the censor can stop the user connecting" is
not a protocol vulnerability here.

### 3.4 Anonymity from the service operator at the network layer

Win's VPN gateways see client source IP addresses. The protocol does not hide
the user from the gateway at the IP layer. Anonymous authentication exists to
decouple *identity* from *session* (`internal/privacytoken`, blind RSA
signatures), but the gateway still sees where packets come from. This is a
VPN, not Tor.

### 3.5 Metadata at the application layer inside the tunnel

What the user does inside the tunnel, including DNS inside the tunnel and TLS
SNI to the final destination, is the application's business. Winn carries
bytes.

### 3.6 Security of the underlying AmneziaWG data plane

Winn does not implement the WireGuard or AmneziaWG cryptographic core. On
Linux the data plane is the external `amneziawg-go` executable
(`internal/directawg/linux_controller_common.go:24`). Vulnerabilities in that
binary's Noise implementation are upstream's, not ours. What *is* in scope is
everything Winn does around it: how it is configured, what key material it is
given, how obfuscation parameters are chosen, and whether the surrounding
policy is fail-closed.

### 3.7 Physical and legal coercion of the user

If a user is compelled to unlock a device or disclose that they use a VPN, the
protocol cannot help. There is no plausible deniability claim and no duress
mode.

### 3.8 Supply chain of the Go toolchain and standard library

The hybrid post-quantum key exchange is implemented by Go 1.26's `crypto/tls`,
not by this repository (see section 5.1). A defect in Go's ML-KEM
implementation is a defect in Winn, but it is not one this codebase can be
audited for. We would welcome a reviewer's opinion on whether that delegation
is the right call, but the implementation itself is out of tree.

---

## 4. Assets

Ranked by what an adversary gains from compromising each.

| # | Asset | Where it lives | Compromise means |
|---|---|---|---|
| S1 | **The fact that a user runs Winn at all** | Observable traffic pattern | Identification of a circumvention-tool user. Highest-severity asset in this model. |
| S2 | Device long-term ML-DSA signing seed | `0600` file on disk, `internal/pqauth/pqauth.go:194` loads it | Impersonation of the device to the controller; ability to request key rotation as that device |
| S3 | AWG pre-shared key (32 bytes, per device, per generation) | Controller state (AES-256-GCM at rest), transiently in `0600` files on the client, and in the `amneziawg-go` process | Ability to decrypt or forge that device's data-plane traffic for that generation |
| S4 | Device X.509 private key (ECDSA P-384) | `0600` PEM on disk, `internal/pki/pki.go:310-317` writes it | Mutual-TLS impersonation of the device to the controller |
| S5 | Controller ML-DSA signing key | Controller host | Ability to sign forged rekey responses and gateway manifests; this is the root of client-side trust |
| S6 | Gateway manifest signing key | Controller host | Ability to redirect clients to an attacker-controlled gateway |
| S7 | Controller state encryption key (32 bytes, AES-256) | `0600` file, `internal/state/state.go:239-246` | Disclosure of all device PSKs at rest |
| S8 | Privacy-token issuer RSA key | `0600` file, `internal/pki/pki.go:262-270` | Ability to mint unlimited anonymous carrier credentials |
| S9 | Audit-log HMAC key | `0600` file | Ability to forge or silently truncate the tamper-evident audit chain |
| S10 | Session traffic contents | In flight | Standard confidentiality loss |
| S11 | ECH server key (X25519) | `0600` file, `internal/echconfig/ech.go:116` | Ability to decrypt the inner ClientHello, exposing the true SNI to the adversary |

Note the ordering. **S1 outranks S10.** In this population, knowing that
someone uses the tool is worse than knowing what they browsed.

---

## 5. Trust boundaries

Enumerated as places where data or authority crosses from something we do not
control into something we do. Each is elaborated with entry points in
[02-ARCHITECTURE-AND-DATA-FLOW.md](02-ARCHITECTURE-AND-DATA-FLOW.md#5-trust-boundaries)
and ranked by exposure in
[03-SECURITY-CODE-MAP.md](03-SECURITY-CODE-MAP.md).

### 5.1 Client to network (fully hostile)

Everything on the wire is adversary-controlled or adversary-observable. This
is boundary zero and the reason the project exists.

### 5.2 Client to controller (authenticated, pinned, not trusted by default)

The client does **not** use the system trust store. `internal/tlsconfig`
constructs a TLS 1.3 configuration with a pinned `RootCAs` pool loaded from a
file (`internal/tlsconfig/tlsconfig.go:120`), `MinVersion == MaxVersion ==
TLS13`, a single-element `CurvePreferences`, session tickets disabled, and
renegotiation forbidden. The negotiated state is re-validated after the
handshake (`internal/tlsconfig/tlsconfig.go:155-182`). A compromised or
compelled public CA (capability A7) therefore does not yield a
man-in-the-middle position.

On top of TLS, the controller's ML-DSA public key is **pinned by
(algorithm, key-id)** on the client, and every rekey response is verified
against that pin (`internal/bootstrap/client.go:207-213`). Breaking the TLS
channel is not sufficient to forge a rekey response.

### 5.3 Client to gateway manifest (signed, replay-resistant, rollback-resistant)

Gateway selection data is not trusted from the network. `LoadVerifiedNodeV2`
(`internal/gatewaymanifest/deployment_v2.go:110`) performs, in order: bounded
size read with `DisallowUnknownFields`; structural validation; strict base64
signature decode; pin lookup by `(AuthAlgorithm, AuthKeyID)`; domain-separated
ML-DSA verification; then rollback, equivocation, gap, and
predecessor-digest checks against retained trust state; then a transparency
inclusion proof. This is the boundary that defends against capability A8
(compelled infrastructure serving a poisoned manifest).

### 5.4 Controller to client (authenticated by mutual TLS plus device signature)

The controller derives the device identity from the *verified* certificate
chain as a SPIFFE URI SAN (`internal/identity/identity.go:14-53`) and then
requires that the device ID inside the signed request equals that certificate
identity (`internal/bootstrap/server.go:174`). A device cannot request rotation
on behalf of another device even with a valid certificate.

### 5.5 Process to operating system (partially trusted)

Winn shells out. On Linux, session bring-up invokes `amneziawg-go`, `awg`,
`ip`, `nft`, and `resolvectl` as external executables. Their stdout is parsed.
This is a real trust boundary with real parsers behind it
(`internal/directawg/status_cli.go`, `internal/awg/applier.go:165`) and it is
ranked accordingly in the code map. Command paths are validated as absolute,
regular, executable files; some call sites additionally enforce a fixed
allow-list, and **some do not**. See
[03-SECURITY-CODE-MAP.md](03-SECURITY-CODE-MAP.md#tier-2-subprocess-and-os-boundary)
for the exact split, which is a live concern rather than a settled defence.

### 5.6 Host application to protocol engine (trusted caller, validated data)

On mobile and desktop the protocol runs behind a C ABI or a subprocess with a
framed duplex protocol. The caller is trusted to be the host app; the *bytes*
it sends are still validated (`datapath/config.go:220`,
`datapath/duplex/duplex.go:289`, `cdatapath/winn_datapath.go:123`).

### 5.7 Disk (trusted for integrity, not for confidentiality against local root)

Private material is written `0600` into `0700` directories through an atomic
write path. Reads go through a TOCTOU-resistant helper that rejects any file
with group or other permission bits (`internal/securefile/securefile.go:280-337`).
**On Unix, file ownership is never verified** - the helpers that would do so are
no-ops (`internal/securefile/permissions_unix.go:7,11,13`). See
[04](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md).

---

## 6. What the protocol defends against

Claims here are claims about intent plus an implementation pointer. They are
not claims that the implementation is correct; establishing that is the
auditor's job.

| # | Defence | Mechanism | Evidence |
|---|---|---|---|
| D1 | Store-now-decrypt-later (A12) | Strict hybrid TLS 1.3 key exchange, single curve offered, no classical fallback group, post-handshake curve re-validation | `internal/tlsconfig/tlsconfig.go:16-27, 85, 134, 165-167` |
| D2 | SNI-based blocking and identification (A2, A5) | Encrypted Client Hello, mandatory and fail-closed: the handshake is rejected unless `state.ECHAccepted` is true | `internal/echconfig/ech.go:194-204, 223-233`; second independent gate at `internal/h3candidate/candidate.go:519-543` |
| D3 | Protocol fingerprinting by shape (A3) | Length padding to fixed buckets, cover traffic, carrier diversity | `internal/carrier/envelope.go:95, 388-398, 59-61` |
| D4 | Protocol fingerprinting by carrier (A2, A5) | The inner session is carrier-agnostic; blocking one carrier does not block the protocol | `internal/carrier/manager.go:19-21`, selection at `manager.go:346` |
| D5 | Domestic CA man-in-the-middle (A7) | Pinned root CA pool, no system trust store, TLS 1.3 only, plus an independent ML-DSA signature pin over the payload | `internal/tlsconfig/tlsconfig.go:120`; `internal/bootstrap/client.go:207-213` |
| D6 | Poisoned or rolled-back gateway directory (A8) | Signed manifest with rollback, equivocation, gap and predecessor-digest checks plus transparency inclusion | `internal/gatewaymanifest/deployment_v2.go:110-188` |
| D7 | DNS interception and leaks (A9) | Gateway endpoints must be IP literals on the supplied-socket and direct-awg paths, so no name resolution happens outside the tunnel; fail-closed nftables plus systemd-resolved policy on Linux | `internal/carrier/supplied_socket.go:319-335`; `internal/directawg/udp.go:16-47`; `internal/directawg/linux_policy.go` |
| D8 | Replay of a rekey request | Fresh 32-byte request ID and nonce, request digest bound into durable state before transmission, server-side reconciliation latch | `internal/bootstrap/client.go:119-146`; `internal/rotation/coordinator.go:194-203`; `internal/bootstrap/server.go:196-230` |
| D9 | Cross-device impersonation | Device ID in the signed request must equal the SPIFFE identity in the verified client certificate | `internal/bootstrap/server.go:174` |
| D10 | Silent audit tampering | HMAC-chained append-only JSONL audit log; server refuses to serve when the audit sink is unhealthy | `internal/audit/audit.go:268-277`; `internal/bootstrap/server.go:69-76` |
| D11 | Identity linkage across sessions (partial) | Anonymous carrier authentication using blind RSA tokens with a single-use redemption ledger | `internal/privacytoken/token.go`; `internal/carrier/authentication.go:106` |
| D12 | Traffic leaking outside the tunnel on Linux | Kill switch installed as a fail-closed nftables batch; policy rollback must succeed before routes are torn down | `internal/directawg/linux_policy.go:58-100`; ordered teardown at `internal/directawg/linux_session.go:197` |
| D13 | Credential exposure in logs | Operational logs emit an HMAC of the request ID under a per-process random key, not the ID itself; `KeyLogWriter` is actively rejected in the carrier | `internal/bootstrap/server.go:387-401`; `internal/carrier/h3.go:439` |

---

## 7. What the protocol does not defend against

Beyond the non-goals in section 3, these are specific weaknesses we already
believe exist. They are listed here rather than buried because volunteering
them is what makes the rest of this package worth trusting. Full detail in
[04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md).

- **The pre-shared key is transport-protected, not KEM-encapsulated.** The
  32-byte AWG PSK is generated by the controller's CSPRNG and sent to the
  device as a base64 JSON field inside the TLS session
  (`internal/state/state.go:530-540`, `internal/protocol/protocol.go:77`). It is
  signed, so it is authentic, but it is not independently encrypted. A break of
  the TLS channel yields the PSK directly. The post-quantum property of the PSK
  is therefore exactly the post-quantum property of the TLS handshake, and
  nothing more. Internal naming calls this a "hybrid PSK", which invites
  misreading.
- **ECH rejection is not retried.** The server marks keys `SendAsRetry`, but no
  client code catches `tls.ECHRejectionError` to re-drive the handshake with the
  server-supplied retry configuration. An ECH rejection surfaces as a plain
  handshake failure. Grep for `ECHRejectionError` and `RetryConfigList` returns
  zero hits tree-wide.
- **The exec allow-list does not cover every exec boundary in its own
  package.** `LinuxExecAllowList` pins path-name strings by exact equality, with
  no symlink resolution and no content digest, and it is per-runner rather than
  per-process. Two exec boundaries in `internal/directawg` are not covered by it
  (`internal/directawg/exec_allowlist.go:22-63`, which documents this candidly).
- **On Unix, `securefile` does not verify file ownership.** A `0600` file owned
  by another user in a writable directory would pass every check.
- **Cover traffic and padding are not calibrated against a measured
  classifier.** We have the mechanism. We do not have evidence that it defeats
  any specific real-world DPI system. Treat D3 as unproven.
- **Only one carrier completes a session end to end, and only on Linux.** See
  section 1 of document 04.

---

## 8. What we most want an auditor to look at

In priority order, given the asset ranking in section 4.

1. **Fingerprintability of the carrier envelope.** The `WCF2` framing is a
   16-byte cleartext header with a literal ASCII magic value `"WCF2"` at offset
   0 (`internal/carrier/envelope.go:23, 400-428`). It sits inside TLS or QUIC,
   so it is not visible to a passive observer of the outer flow. We want
   confirmation that this is true in every path, and that no code path emits it
   unwrapped. This is asset S1.
2. **Whether the padding and cover-traffic design actually resists a
   size-and-timing classifier**, or whether the fixed bucket set itself becomes
   the fingerprint.
3. **The PSK distribution design** (section 7, first bullet). We would like an
   opinion on whether the PSK should be KEM-encapsulated independently of the
   transport, and what that would cost.
4. **The manifest trust-state machine** (`internal/gatewaymanifest/deployment_v2.go`)
   - rollback, equivocation, gap and transparency logic is where a compelled
   operator attack would land, and it is dense.
5. **The subprocess parsers** (`internal/directawg/status_cli.go`,
   `internal/awg/applier.go:165`, `internal/directawg/linux_policy.go:628`).
   `linux_policy.go:628` verifies nftables set membership with a
   `strings.Contains` substring match rather than a structural parse.
6. **The supplied-socket adoption path**, which is one day old at the time of
   writing and is the mechanism that will carry Android.

---

## 9. Out-of-scope infrastructure

The following are real parts of the service but are not this repository and
are not proposed for this audit: the Flutter client application, the gateway
provisioning and orchestration systems, the billing and account systems, the
website, and the `amneziawg-go` and `amneziawg-tools` upstream projects.
