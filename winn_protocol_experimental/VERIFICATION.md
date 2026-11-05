# Winn Protocol v2 Verification Record

Date: 2026-07-23

Decision: every implementation-owned gate passes. The isolated implementation
is a production candidate for controlled integration and staging, subject to
the owner-controlled no-go items in `PRODUCTION_READINESS.md`.

## Scope and environment

- Implementation: `winn_protocol_experimental/`; it is not linked into the
  shipping Win's VPN app.
- Host: MacBook Pro (Mac17,8), Apple M5 Pro, 48 GB, macOS 26.5.2.
- Go: 1.26.5 `darwin/arm64`.
- OpenSSL: 3.6.3.
- Docker client/server: 29.6.2/29.5.2.
- ADB: 1.0.41.
- Physical reference: Samsung SM-S948U1, Android, `arm64-v8a`, over USB.
- Current implementation: 81 Go files, 33 test files, 93 named tests, eight
  fuzz targets, two benchmarks, and ten commands.

## Complete automated gate

`./scripts/verify.sh`: **PASS**.

The final clean invocation completed:

- module integrity and `gofmt` checks;
- POSIX shell parsing for every script;
- `go vet ./...`;
- Staticcheck 2026.1 with no finding;
- gosec v2.25.0 with no unsuppressed production-code finding;
- govulncheck v1.6.0 with zero reachable vulnerabilities (one required-module
  advisory exists, but the implementation imports no affected symbol);
- `go test -race ./...`;
- all unit, integration, negative, state, and interoperability tests;
- eight bounded fuzz campaigns;
- all-profile control-plane smoke;
- identity-mode H3 and H2 carrier smoke;
- advanced signed-manifest, transparency, ECH, blind-token, anonymous H3, and
  high-risk privacy smoke;
- two independent byte-for-byte reproducible command builds;
- a disposable real PostgreSQL transactional test.

Final summary:

```text
PASS: modules, formatting, shell syntax, vet, staticcheck, gosec,
govulncheck, race, fuzz, interoperability, ECH, transparent manifests,
anonymous carrier authorization, path migration, recovery, E2E,
reproducibility, and PostgreSQL
```

The eight fuzz targets cover the peer-key parser, request validator, response
validator, ML-DSA signature decoder/verifier, carrier signature headers, H2
framing, WCF2 envelopes, and privacy-token headers.

## Cryptographic and bootstrap evidence

Tests established:

- all three TLS profiles complete fresh hybrid ECDHE+ML-KEM TLS 1.3
  handshakes;
- a classical-only client, wrong suite, resumption attempt, missing ECH, and
  rejected ECH fail closed;
- OpenSSL independently interoperates with all three hybrid groups and
  verifies standardized ML-DSA-65/87 public keys and signatures;
- a valid X.509 identity cannot substitute an unregistered ML-DSA key;
- every rekey field is signed, exact retry is idempotent, generations are
  monotonic, and controller/device PSKs match byte for byte;
- the controller emits a different random non-zero 32-byte PSK at every
  generation;
- file and PostgreSQL state preserve crash recovery, encryption, replay
  conflict, revocation, and exact pending-request reconciliation.

Host control-plane result:

```text
PASS: 3 strict hybrid suites, matching controller/device PSKs,
monotonic rotation, and revocation
```

PostgreSQL result:

```text
PASS: PostgreSQL schema, transactional store tests, controller CLI,
pin set, and PSK agreement
```

## Gateway, privacy, and carrier evidence

Tests exercised:

- expiry-bounded ML-DSA-signed gateway manifests;
- signed append-only transparency receipts, full-chain inclusion, independent
  checkpoint matching, file locking, and atomic publication;
- manifest-bound endpoint, suite, ECH, authorization-mode, token-key, and
  inner-MTU policy;
- RFC 9849 ECH on controller, token issuer, H3, and H2 handshakes;
- RFC 9474 blind RSA issuance with RSA-3072/4096, SHA-384 PSS, authenticated
  blinded-request binding, and issuer/carrier trust separation;
- anonymous carrier authorization with no stable client certificate, one-time
  token redemption, and ephemeral ML-DSA proof of possession;
- finite protected token pools that fail closed when exhausted;
- RFC 9298 CONNECT-UDP over H3/QUIC DATAGRAM and the WCF2 H2 fallback;
- shared session/sequence epoch, duplicate suppression, and a handoff window
  capped at one second and 128 datagrams;
- adaptive authenticated inner-MTU probes and QUIC
  `DatagramTooLarge` reduction;
- IPv6-first Happy Eyeballs, signed IP hints, and DNS64/NAT64 synthesis;
- bucket padding, jittered keepalives, and bounded opt-in cover frames;
- fixed AWG backend enforcement and rejection of arbitrary targets.

The live migration test created a second bound UDP socket, validated it on the
existing H3 connection with RFC 9000 path probing, switched the connection,
and successfully relayed a new echo. Fresh focused tests also passed bounded
same-sequence handoff redundancy and real H3 shutdown to independently
listening H2 recovery:

```text
PASS: TestAuthenticatedH3ConnectUDPEndToEnd
PASS: TestManagerBoundsHandoffRedundancyAndReusesSequence
PASS: TestRealCarrierSelfHealingH3ToH2
```

Command smoke results:

```text
PASS: authenticated H3 and H2 carrier commands relayed fixed-backend UDP
with one stable session/generation

PASS: signed transparent manifest, mandatory ECH, blind split-trust
issuance, anonymous H3 carrier, high-risk padding/cover, and one-time
redemption
```

## Release and supply-chain evidence

`scripts/build_release.sh` built and checksum-verified a fresh 289 MiB release:

- 42 executables: all ten commands for Linux amd64/arm64, macOS arm64, and
  Windows amd64, plus Android arm64 rekey and carrier clients;
- `go version -m` metadata for every executable;
- pinned `go.mod` and `go.sum`;
- 23 dependency/standard-library license files;
- CycloneDX 1.6 SBOM;
- a complete SHA-256 manifest.

Every manifest checksum passed. Two independent builds of all ten host commands
were byte-for-byte identical. A fresh OpenSSL `SLH-DSA-SHA2-192s` key signed
the real SHA-256 manifest, and independent verification returned:

```text
Signature Verified Successfully
```

## Physical Android reference test

The repository-required phone sequence was completed:

1. Uninstalled `org.winsvpn.app`.
2. Installed `build/app/outputs/flutter-apk/app-release.apk`.
3. Verified APK SHA-256
   `4758573d35e183c72c598805fa192d26ed362393dd6182247416b0f10b14dd13`.
4. Cold-launched `org.winsvpn.app/.LauncherReal`; Android resumed
   `.MainActivity` in 305 ms and the process remained alive.
5. Inspected the app process log. There was no fatal exception or
   VPN/AWG/Xray/service startup error. Samsung graphics-driver probes,
   including the missing optional `libpenguin.so`, were nonfatal.
6. Cross-compiled and deployed the isolated Android arm64 rekey and carrier
   clients into a private temporary directory.
7. Required ECH and all three hybrid profiles negotiated through `adb reverse`.
8. For every profile, the phone-applied and controller-applied PSKs matched
   byte for byte.
9. The phone retained the same Winn session and AWG generation while an
   authenticated H2 fallback relayed a UDP payload through the fixed backend.
10. The carrier audit chain verified and the script removed its device
    binaries, credentials, reverse ports, processes, PSKs, and host work area.

Result:

```text
PASS: Android SM-S948U1 negotiated all 3 hybrid suites, matched controller
PSKs, and relayed authenticated H2 fallback UDP with a stable Winn session
```

The Android protocol proof uses gated lab file adapters so the experiment does
not change a live customer tunnel. The shipping APK was smoke-tested but does
not yet contain or invoke this isolated protocol.

## Boundary of evidence

This establishes correct behavior across the tested host, database, OpenSSL,
carrier, release, and physical-Android boundaries. It does not constitute an
independent audit, a FIPS 140 validation, production KMS/PKI approval, a
shipping-app integration, or proof that a deployed carrier is invisible or
always bypasses censorship.

Winn implements validated migration of one live QUIC path and bounded
application-level handoff duplication. It does **not** claim conformance to the
still-draft simultaneous multipath-QUIC extension. Production promotion remains
no-go until the applicable external gates in `PRODUCTION_READINESS.md` have
accountable sign-off.
