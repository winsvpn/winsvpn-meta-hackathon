# Winn Protocol Algorithm Profiles — control plane v2 + standalone datapath v3

Winn uses a small, fixed algorithm portfolio. Algorithm agility is expressed by
versioned suites, not by accepting arbitrary client-selected primitives.

This document covers **two co-existing families**: the v2 control-plane
(`winn/2`, `internal/protocol`, `internal/tlsconfig`) that negotiates
per-peer AWG PSKs, and the standalone v3 datapath (`winn/3`,
`winn3/core`, `winn3/tun`, `winn3/gateway`) that owns its handshake,
crypto and datapath and does **not** carry AWG datagrams. Prior revision
titled "v2 only" was stale per audit `docs/handoff/ALGORITHM_PROFILES_AUDIT_20260812_doc_algorithm_profiles.md` — this revision retains every true v2 claim and corrects the false/overgeneralized ones below without touching code.

## Online protocol profiles

### v2 control-plane (TLS) suites — the AWG-PSK rekey path

| Suite | TLS key establishment (`crypto/tls` CurveID) | PQ application authentication | Intended use |
|---|---|---|---|
| `x25519-mlkem768` | `X25519MLKEM768` | ML-DSA-65 | Default balance of performance, size, and security |
| `p256-mlkem768` | `SecP256r1MLKEM768` | ML-DSA-65 | Environments standardized on NIST P-256 |
| `p384-mlkem1024` | `SecP384r1MLKEM1024` | ML-DSA-87 | Higher-bandwidth conservative profile |

*Evidence:* `internal/protocol/protocol.go:32-34` defines the three suites; `internal/tlsconfig/tlsconfig.go:26-33 ParseSuite` maps each to exactly the CurveID shown; `internal/protocol/protocol.go:118-127 RequiredAuthAlgorithm` maps the first two to `mldsa65`, the third to `mldsa87`.

**Server enforcement vs client advertisement:** The *server* enforces exactly one named group: `internal/tlsconfig/tlsconfig.go:95 CurvePreferences: []tls.CurveID{suite.Curve}`. The *client* intentionally advertises a superset for fingerprint reasons: `internal/tlsconfig/tlsconfig.go:645 goDefaultCurveOrder` and `:679 ClientCurvePreferences` returns `goDefaultCurveOrder[required:]` (up to 7 groups for `x25519-mlkem768`). Negotiation is still pinned to exactly one group by `VerifyConnection ValidateKeyAgreement` (`internal/tlsconfig/tlsconfig.go:702-715`, `:780`) which rejects any other CurveID. Prior prose "each controller endpoint permits exactly one named group" was false for the client-advertisement half.

**Handshake invariants:** TLS 1.3 only (`MinVersion=MaxVersion=VersionTLS13` at `internal/tlsconfig/tlsconfig.go:93-94` / `:740-741`), fresh handshakes (`SessionTicketsDisabled=true`), ALPN set per-role (`http/1.1` for controller/token-issuer at `:40`, `h2`+`http/1.1` or `h3` for carrier — e.g., `cmd/winn-carrier-server/main.go:385` `[]string{h2.NextProtoTLS,"http/1.1"}`). Prior prose "ALPN `http/1.1`" was true for controller but incomplete for carrier.

**Authentication — identity vs anonymous (correction):** Prior prose "mutual P-384 X.509 authentication ... mandatory" for controller *and* carrier was **FALSE** for anonymous carrier. Correct split:
- **Identity mode:** mutual P-384 X.509 (keys generated via `elliptic.P384` at `internal/pki/pki.go:75,95,117`) + suite-mapped ML-DSA signature (`protocol.ValidateRequest` + `pqauth.VerifyRequest/VerifyResponse`) — server `tls.RequireAndVerifyClientCert` (`internal/tlsconfig/tlsconfig.go:46`).
- **Anonymous-token mode:** server `tls.NoClientCert` (`internal/tlsconfig/tlsconfig.go:53 ServerAnonymousForALPN`), no CA DN disclosed (cover profile `:220-230 ClientAuth: NoClientCert`), authentication via RFC 9474 blind token committing to a one-time ML-DSA key (`internal/privacytoken/token.go:2,34,113 Algorithm=rsabssa-sha384-pss-randomized RSA-3072/4096 blindrsa.SHA384PSSRandomized`, `carrierauth` verifies that, not X.509). `TrustWebPKI`+stable client cert is explicitly refused (`ErrTrustWebPKIWithClientCertificate` at `internal/tlsconfig/tlsconfig.go:500`).
Both modes still require the suite-mapped ML-DSA signature on the control-plane message; classical/PQ diversity holds per-mode.

**ECH:** RFC 9849 ECH is mandatory on the *Winn profile* (`internal/echconfig/ech.go:200-202` + `:229-231` error "winn requires accepted ECH" + callers `ConfigureClient/ConfigureServer(..., true)` in `cmd/winn-server/main.go:204`, `cmd/winn-carrier-server/main.go:340-343`, `cmd/winn-token-issuer/main.go:135`). The *cover listener* installs the same keys via `ConfigureServerCover` (`internal/echconfig/ech.go:237-259`) **without** requiring `ECHAccepted` — intentionally serving non-ECH probers the public site (Trojan/VLESS-REALITY pattern). Prior prose "mandatory ... required, never silently downgraded" is true for Winn profile, not for cover. ECH uses standardized X25519/HPKE `DHKEM(X25519,HKDF-SHA256)` (`internal/echconfig/ech.go:26 kemX25519HKDF256=0x0020/kdfHKDFSHA256=0x0001`, `Generate` X25519).

ML-KEM is NIST FIPS 203. ML-DSA is NIST FIPS 204. The named TLS groups are implemented by Go 1.27 `crypto/tls` (`go.mod:3 go 1.27.1`); Winn does not implement KEM arithmetic, TLS transcript construction, or a custom combiner.

### Standalone datapath v3 (winn3) — no TLS, no AWG

| Property | Value | Where |
|---|---|---|
| Wire label | `winn/3` + `winn3-x25519-mlkem768-chacha20poly1305-sha256` | `winn3/core/params.go:19,24` |
| Classical DH | X25519 (32B keys) | `winn3/core/params.go:35 KeySize=32`, `transcript.go` `labelDHEphStatic` etc. |
| Post-quantum ratchet | ML-KEM-768 (rekey via control plane) | `winn3/core/transcript.go:50 labelPQ="winn3 pq ratchet v1"` |
| AEAD | ChaCha20-Poly1305, 16B tag, 12B nonce (4B salt+8B counter) | `winn3/core/params.go:37-49` |
| Transcript / KDF | SHA-256, HKDF-SHA256 | `winn3/core/transcript.go` (`hkdf extract/expand`) |
| Admission tag | HMAC keyed by `GatewayParams.AdmissionKeys` + `GatewayID`, TagSize 16-32 (default 32) | `winn3/core/params.go:66-79`, `admission.go` |
| Inner MTU / carrier | Adaptive via `winn3/carrier/sizing.go`, `winn3/tun/mtu.go`, `session/pathmtu.go` | (see winn3 docs) |

There is no ciphersuite negotiation on this datapath (suite is transcript input, `winn3/core/params.go:7` "NEVER sent on wire"). The gateway datapath does not use TLS or AWG packet formats.

## Symmetric and hashing primitives

| Purpose | Primitive | Notes |
|---|---|---|
| AWG peer secret (v2 legacy) | 256 random bits | Generated by the OS CSPRNG; all-zero rejected (`internal/state/state.go:531-541`, `protocol.ValidatePeerPublicKey`). Only for v2 AWG-PSK path; **standalone v3 datapath does not use AWG** |
| winn3 datapath AEAD | ChaCha20-Poly1305 | Per-session 32B key, 12B nonce (4B derived salt + 8B counter) — `winn3/core/params.go:35-49`; tag 16B |
| winn3 transcript/KDF | SHA-256, HKDF-SHA256 | `winn3/core/transcript.go` labels `winn3 chain next`, `winn3 dh ...`, `winn3 pq ratchet` |
| winn3 admission tag | HMAC (gateway AdmissionKeys × time buckets) | `winn3/core/params.go:66-108 MaxAdmissionHMACs=64`, `Freshness DefaultBucketWindow=10s MaxSkew=60s` |
| Single-node state (v2) | AES-256-GCM | Fresh random nonce and v2 associated data `winn-protocol-controller-state/v2` — `internal/state/state.go:28 envelopeFormat=winn-state-aes256gcm/v2 :31 stateAssociatedAD` |
| PostgreSQL response envelopes (v2) | AES-256-GCM | Associated with controller and request IDs (`internal/state/postgres.go:765 response_envelope`) |
| Audit chain | HMAC-SHA-256 | Fsynced chain; device IDs are separately keyed-hashed (`internal/audit/audit.go:24 winn-audit-hmac-sha256/v1 :268 hmac+recordDomain :276 deviceDomain :169 Sync`) |
| Request/key identifiers | SHA-256 | Non-secret binding and replay identifiers (`protocol.RequestDigest`, `protocol.KeyID`) |
| Anonymous carrier authorization | RFC 9474 RSABSSA-PSS-SHA384, RSA-3072/4096 | Blind issuance; single-use redemption (`RedemptionCache ErrAlreadyRedeemed`); token commits to an ephemeral ML-DSA key — `internal/privacytoken/token.go:34,113,168,213` |
| ECH configuration | RFC 9849 DHKEM(X25519, HKDF-SHA256) HPKE | Protects the real ClientHello/SNI; required on Winn profile, optional on cover listener (see above); never silently downgraded (`echconfig.ConfigureClient/Server required` gate) |
| AWG data plane (v2 legacy) | Existing AWG/WireGuard construction | Winn only manages its optional per-peer PSK (`directawg`). **Not the standalone v3 datapath** |

The state and audit keys are separate 32-byte credentials. Reusing either key for TLS, ML-DSA, AWG, or each other is forbidden (`internal/pki/pki.go` generates `state.key` and `audit.key` independently, 32B each, stored at distinct paths; `internal/state` reads only state key, `internal/audit` reads only audit key).

**Gateway inner DNS resolver (winn3 datapath descriptor resolver):** `cmd/winn3-gateway/resolve.go` is a forwarder answering UDP/53 at this gateway's `-inner-v4` (and TCP/53 when `-forward` + `-resolver` + `CAP_NET_BIND_SERVICE`, `resolve_tcp.go`) — NOT the data-plane crypto but the host-level resolver the profile expects. It is **not advertised** until descriptors carry it. Staged descriptor format v3 (2026-08-12, `server/wins_control_plane_setup_ONETOUCH.sh:8713 VERSION=3`) adds REQUIRED `inner_resolver_v4` (dotted-quad, in `PLAIN_IPV4_FIELDS`, validated `winn3_is_inner_ipv4` + `winn3_inner_router_in_pool` + reserved via `allocate_winn3_inner_ip`; secret fields unchanged). Prior revisions claiming descriptor has 17 fields / no resolver are stale for v3. See `docs/handoff/WINN3_DESCRIPTOR_V3_RESOLVER_20260812_v3_descriptor_v3_field.md` and `V3_RESOLVER_STANDUP...md` — this profile doc does not replace that design; it only records the algorithm inventory.

## Offline release profile

Release checksums may be signed with `SLH-DSA-SHA2-192s` using `scripts/sign_release_slhdsa.sh`. SLH-DSA is NIST FIPS 205 and gives a hash-based algorithm-diversity option for offline software provenance. It is not placed on the online rekey path because its signature size and signing cost are poor tradeoffs for mobile key rotation.

Generate and guard the release key offline:

```sh
openssl genpkey -algorithm SLH-DSA-SHA2-192s -out release-slhdsa.pem
./scripts/sign_release_slhdsa.sh RELEASE_DIR release-slhdsa.pem
./scripts/verify_release_slhdsa.sh RELEASE_DIR TRUSTED_PUBLIC_KEY.pem
```

The public key must be distributed through a channel independent of the release artifacts it authenticates.

## Algorithms deliberately not added

- ML-KEM alone: hybrid ECDHE+ML-KEM avoids betting the deployment on one family.
- SLH-DSA on every request: standardized and conservative, but unnecessarily large and slow for this online use.
- FN-DSA/Falcon or HQC: not used until final standards, mature implementations, and a concrete protocol need justify a new Winn version.
- HPKE layered over TLS: it would add state and failure modes without improving endpoint compromise resistance. HPKE is used only where the ECH standard specifies it, not as a second proprietary payload layer.
- Always-on simultaneous multipath QUIC: the current IETF work remains a draft and the selected QUIC stack does not offer a production multipath scheduler. Winn implements standardized RFC 9000 path validation/migration plus bounded application-level handoff redundancy.
- Novel ciphers, KDFs, or AWG packet formats: outside Winn's control-plane scope.

## Primary references

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [IETF ECDHE-MLKEM TLS work](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [RFC 9881: ML-DSA X.509 identifiers](https://www.rfc-editor.org/rfc/rfc9881.html)
- [RFC 9849: TLS Encrypted ClientHello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [RFC 9474: RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html)
- [Go 1.27 release notes](https://go.dev/doc/go1.27)
- [OpenSSL 3.6 ML-DSA operations](https://docs.openssl.org/3.6/man1/openssl-pkeyutl/)
- [WireGuard known limitations](https://www.wireguard.com/known-limitations/)
