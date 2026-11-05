# Winn Protocol v3 — Authoritative Implementation Plan

Status: approved implementation source of truth  
Baseline date: 2026-07-23  
Project boundary: all implementation remains isolated inside
`winn_protocol_experimental`

This plan supersedes the previous contents of
`WINN_PROTOCOL_V3_IMPLEMENTATION_PLAN.md`. The separate Opus recommendation is
retained as review history, but this document controls implementation,
acceptance, and completion.

## Strategy

Winn v3 is an extension of the tested Winn v2 foundation, not a from-scratch
protocol rewrite. The work is organized around:

1. A measurement harness and frozen acceptance rubric before feature expansion.
2. A Linux vertical slice proving the three-second contract with raw AWG and
   HTTP/3.
3. Adaptive carrier breadth, mobility, active-probing resistance, and
   cross-platform reference clients.
4. Native two-hop separation followed by required traffic-analysis resistance.
5. Evidence-based scoring, with no score raised before its gate passes.

Maximum Privacy is allowed to land after the Core vertical slice, but it remains
part of the overall Winn v3 goal. The project is not complete while metadata
anonymity remains below its 4/5 acceptance target.

## Objective and non-negotiable boundaries

Build and validate a native Winn VPN protocol suite that combines:

- AmneziaWG (AWG) as the encrypted data plane.
- A standards-based hybrid post-quantum-resistant control plane.
- Adaptive raw UDP, HTTP/3, HTTP/2, and camouflage carriers.
- Fast preparation, connection, reconnection, mobility, and
  make-before-break failover.
- Passive-DPI and active-probing resistance.
- Native Winn two-hop routing and traffic-analysis-resistant privacy modes.
- A hard three-second outcome: verified connected or clean failure.

Protocol boundaries:

- Say “post-quantum resistant,” never “quantum proof.”
- Do not invent a cipher, cryptographic primitive, or merged AWG/Xray handshake.
- Require X25519 plus ML-KEM-768; never use ML-KEM alone.
- Keep Xray an optional, external, replaceable camouflage sidecar.
- Do not use Nym software, infrastructure, network access, branding, or source
  code.
- Treat split trust, padding, fixed cells, cover traffic, mixing, and multipath
  as potentially established prior art. Independently implement only what the
  Winn threat model requires.
- Do not claim “undetectable,” “fastest,” or “anonymous against all observers.”

## Winn v2 reuse baseline

The following capabilities exist in v2 and pass the current local verification
gates. Reuse and extend them rather than reimplementing them:

| Capability | v2 evidence | v3 action |
|---|---|---|
| Hybrid ECDHE plus ML-KEM TLS 1.3 | Implemented and negative-tested | Reuse under `winn/3` |
| X.509 plus ML-DSA authentication | Implemented | Reuse |
| Unique 32-byte AWG PSK rotation | Implemented | Reuse through preparation |
| ECH, downgrade, replay, expiry, revocation | Implemented fail-closed | Preserve without weakening |
| H3 CONNECT-UDP and H2 fallback | Implemented and integration-tested | Adapt to the common mode interface |
| RFC 9000 path validation/migration | Implemented and live-tested | Reuse |
| Signed gateway manifest and checkpoint | Implemented as manifest v1 | Extend to manifest v2 |
| Blind one-time carrier credentials | Implemented | Reuse with independent relay credentials |
| Encrypted file and PostgreSQL state | Implemented | Reuse |
| Fsynced HMAC audit chain | Implemented | Reuse |
| Reproducible builds, SBOM, scanners | Implemented | Extend to new commands and clients |

“Implemented” means present and locally release-gated. It does not mean that
deployment-owner controls, independent review, live AWG integration, or
real-world censorship validation are complete.

## Winn v3 build surface

Winn v3 adds:

1. A `Prepare`/`Readiness` engine and the three-second connection state machine.
2. A production raw-AWG/UDP carrier adapter whose readiness is proved by the
   real AWG handshake, authenticated tunnel bytes, protected DNS, and an
   inner-tunnel canary—never by a bespoke public probe.
3. A common adapter layer for existing H3/H2 and new camouflage/two-hop
   carriers.
4. Xray REALITY plus XHTTP and WebSocket-over-TLS adapters.
5. Adaptive `fast`, `auto`, `stealth`, `private-relay`, and
   `maximum-privacy` modes.
6. Native entry/exit separation with independent one-time credentials.
7. Fixed-cell framing, bounded mixing, padding, jitter, cover budgets, and
   circuit rotation.
8. An append-only measurement harness and isolated reference clients.

## Success criteria

### Three-second contract

For a usable interface with RTT at or below 250 ms, packet loss at or below 3%,
valid unexpired credentials, a current signed manifest, and at least one
reachable signed node:

- Connection latency: p50 at or below 800 ms, p95 at or below 1.5 seconds, and
  p99 at or below 3 seconds.
- Every `Connect()` returns verified success or a fully torn-down failure within
  3 seconds.
- No `online` state is emitted until all four predicates hold:
  1. a fresh AWG handshake;
  2. authenticated bidirectional tunnel bytes;
  3. protected DNS through the winning tunnel; and
  4. a tunnel-only canary bound to the winning candidate.
- Fast mode preserves at least 90% of the direct AWG throughput baseline.

No implementation can guarantee a successful connection within three seconds
on every network. The enforceable contract is a deterministic, verified success
or clean failure within three seconds.

### Score contract

- Every Performance and Access category must reach at least 4/5.
- Metadata anonymity must reach at least 4/5 under the declared adversary model.
- Scores are raised only after archived acceptance evidence passes.
- Core two-hop alone is capped at 3/5 for metadata anonymity.
- Metadata anonymity becomes eligible for 4/5 only after fixed-cell framing,
  mixing, jitter, cover, relay separation, and correlation tests pass.

## Protocol architecture

### Control and data planes

- Keep AWG as the encrypted data plane.
- Use authenticated hybrid TLS 1.3 with the `X25519MLKEM768` group for the
  default control plane.
- Use the authenticated control plane to install and rotate a unique, random,
  non-zero 32-byte AWG preshared key.
- Require the selected ML-DSA profile in addition to classical X.509
  authentication.
- Require RFC 9849 ECH on every public Winn controller, token issuer, H3, H2,
  and native relay TLS endpoint. Missing or rejected ECH fails closed.
- Do not provide a classical-only network fallback.
- Introduce protocol identifier `winn/3`, generic manifest v2 transports, and
  WCF3 framing.
- Preserve strict expiry, revocation, replay, downgrade, suite, audience,
  manifest, and checkpoint validation.

An explicitly gated local lab profile may bypass public discovery requirements
only for tests. Lab mode must never be accepted by a production readiness gate.

### Manifest v2

Manifest v2 describes typed transports instead of hardcoding H3/H2 fields. Each
node entry binds:

- Node and operator identity.
- Entry, exit, controller, issuer, or combined lab role.
- Transport type and endpoint.
- TLS name, ECH configuration, ALPN, and hybrid suite.
- Authorization mode and token verification key.
- Public AWG key, carrier-only fixed backend, and inner-MTU range. Direct AWG
  has no fixed backend or carrier token: it accepts only the rotating
  control-plane-installed AWG PSK authorization mode.
- Explicit two-hop circuit, entry/exit role, operator, provider, transport, and
  independent credential-domain bindings.
- Regional camouflage policy identifier where applicable.
- Capability flags, sequence, issue time, expiry, previous digest, and signer.

Clients reject unknown required capabilities, ambiguous duplicate transports,
role conflicts, invalid regional policy, expired entries, and manifests that do
not extend the pinned checkpoint. They persist the highest accepted manifest
sequence, digest, and transparency checkpoint; rollback, gaps, equivocation, or
checkpoint non-extension fail closed.

### Common carrier adapter

The frozen click-time adapter boundary is:

- `Candidate.Descriptor() -> CandidateDescriptor`
- `Candidate.Dial(ctx, binding) -> CandidateConnection`
- `CandidateConnection.FreshAWGHandshake(ctx, binding)`
- `CandidateConnection.VerifyBidirectional(ctx, binding)`
- `CandidateConnection.VerifyProtectedDNS(ctx, binding)`
- `CandidateConnection.VerifyTunnelCanary(ctx, binding)`
- `CandidateConnection.Commit(ctx, binding)`
- `CandidateConnection.Health()`
- `CandidateConnection.Close()`

Background preparation may use carrier-specific components, but must emit an
immutable `Readiness` snapshot and prepared `Candidate` objects before click
time. Every click-time call carries the exact profile, manifest digest, node
and candidate IDs, Winn session, AWG generation, sequence epoch, nonce, and
expiry in one immutable `Binding`. Migration is a carrier-specific operation
on an already authenticated connection and must preserve that binding.

### Carrier suite

#### Raw AWG over UDP

- Add a real production adapter; the current `DirectUDP` mobility enum is not an
  implementation.
- Do not invent a public UDP probe or probe key. Readiness requires a fresh,
  authenticated AWG handshake for the signed gateway key and current rotating
  PSK, bidirectional counter movement, candidate-isolated protected DNS, and an
  inner-tunnel canary.
- Require a numeric signed endpoint, connected/pinned UDP socket, and the exact
  candidate-local AWG source endpoint so a first-sender packet cannot hijack
  the relay.
- Apply AWG peer configuration only from a verified manifest and control-plane
  generation, in a candidate-isolated interface or namespace.
- Commit platform routes, DNS, and kill-switch state only after every online
  predicate passes; tear them down synchronously on failure.
- Never duplicate user datagrams over raw and wrapped carriers simultaneously
  for one peer. WireGuard endpoint roaming can flap between competing sources.

#### HTTP/3 and HTTP/2

- Adapt the existing RFC 9298 CONNECT-UDP and WCF2/H2 implementations to the
  common interface and WCF3 bindings.
- Preserve QUIC datagrams, adaptive MTU, path validation/migration, and bounded
  make-before-break handoff.
- H2 remains a compatibility fallback, not the preferred performance path.

#### Camouflage

- Use Xray REALITY plus XHTTP as the primary optional camouflage sidecar.
- Use WebSocket over TLS as a structurally different secondary fallback.
- Never expose Xray control credentials or configuration to untrusted manifest
  publishers.
- Bind sidecar process identity, configuration digest, endpoint, and lifecycle
  to the selected candidate.
- A failed sidecar must fail closed without bypassing the kill switch.

#### Native two-hop

- Establish `client → entry → exit → internet`.
- Authenticate to the entry using a blind one-time credential.
- Establish fresh end-to-end hybrid TLS through the entry to the exit.
- Carry AWG/WCF only after the exit channel is authenticated.
- Use independent entry and exit credentials and identifiers.

### QUIC resumption and 0-RTT

QUIC 0-RTT is not on the Core critical path and remains disabled initially.
The three-second contract must first pass using prepared live carriers, normal
authenticated handshakes, and QUIC migration.

0-RTT may be enabled later only after a separate security gate proves:

- The exact early-data message is explicitly safe to replay.
- No early request redeems a blind token, rotates a key, changes trust,
  allocates a durable tunnel, or mutates manifest/security state.
- Session tickets bind the manifest digest, node, transport, ALPN, suite,
  authorization class, and short expiry.
- Cluster-wide anti-replay state bounds acceptance across every server instance.
- Rejection and retry cannot double-process early data.
- Anonymous and identity authorization receive separate documented profiles.
- A full 1-RTT authenticated state and all online predicates are still required
  before user traffic or `online`.

If these conditions remove the latency benefit or add unacceptable linkability,
leave 0-RTT disabled. TLS session tickets and QUIC resumption must be included in
the metadata-linkability review.

### Active-probing threat model

Assume a censor can:

- Inspect packet size, timing, direction, endpoint IP, TLS/QUIC fingerprints,
  SNI/ALPN visibility, and connection behavior.
- Block UDP, TCP ports, IP ranges, DNS answers, TLS names, or protocol
  fingerprints.
- Connect to suspected Winn endpoints and send malformed, partial, replayed, or
  ordinary browser traffic.

Required behavior:

- Unauthenticated probes never receive a Winn-specific success, error, timing,
  certificate, ALPN, or close signature.
- REALITY decoy/target selection is treated as a regional operational policy,
  not a hardcoded protocol constant.
- The signed regional candidate set contains only plausible, reachable targets
  that pass legal, operational, fingerprint, and in-region reachability review.
- WebSocket/TLS presents a defensible browser-compatible HTTP/TLS profile and
  indistinguishable failure behavior.
- Laboratory DPI results are engineering evidence only. They are never labeled
  proof of real in-country circumvention.
- Every stealth carrier passes both passive-DPI and active-probe suites.

## Modes

- `fast`: race two prepared raw-AWG exits.
- `auto`: race raw AWG and H3; keep H2 and the best allowed camouflage path
  ready as fallbacks.
- `stealth`: race REALITY/XHTTP and WebSocket/TLS; do not expose direct UDP.
- `private-relay`: race two prepared basic two-hop entry circuits.
- `maximum-privacy`: race two prepared two-hop privacy circuits using fixed
  cells, mixing, jitter, cover, and rotation.

The selected mode determines allowed carriers. A fallback must never silently
weaken the mode—for example, Stealth cannot fall back to raw UDP and
Maximum Privacy cannot fall back to a single-hop path.

## Public state and API behavior

States:

- `cold`
- `preparing`
- `ready`
- `connecting`
- `online`
- `stopping`
- `stopped`
- `failed`

Operations:

- `Prepare(profile)`
- `Readiness()`
- `Connect(profile, deadline=3s)`
- `Stop()`
- `Status()`
- `WatchEvents()`
- `RefreshManifest()`
- `OnNetworkChange(network)`

Required semantics:

- `Prepare` is idempotent for an unchanged profile and manifest.
- A new profile cancels and securely disposes incompatible prepared state.
- `Readiness` returns profile, manifest digest/expiry, PSK generation/expiry,
  unused credential count, prepared carrier IDs, probe freshness, and blockers.
- Concurrent equivalent `Connect` calls coalesce onto one attempt.
- A conflicting `Connect` returns `connect_in_progress`.
- `Connect` always enforces its own three-second deadline. If readiness is cold
  or expired, it may attempt a cold connection but does not extend the deadline.
- `Stop` is idempotent and cancels preparation, connection races, probes, and
  cover traffic before removing routes and DNS state.
- `OnNetworkChange` validates the new path and performs make-before-break
  migration while the kill switch remains active.
- Every state event carries a monotonic attempt ID, timestamp, mode, candidate
  ID where applicable, and stable machine-readable reason code.

Primary failure codes:

- `connect_deadline_exceeded`
- `not_ready`
- `manifest_invalid`
- `credentials_exhausted`
- `no_reachable_candidate`
- `handshake_failed`
- `dns_verification_failed`
- `canary_failed`
- `mode_policy_violation`
- `network_changed`
- `stopped_by_user`

## Preparation and three-second connection

### Background `Prepare`

Maintain:

- A current, verified signed manifest and cached signed IP/DNS hints.
- Eight unused blind authorization credentials per eligible authorization
  class.
- A fresh hybrid bootstrap/rekey and short-lived pending AWG PSK.
- Continuous carrier-authenticated readiness checks with bounded frequency and
  jitter. Raw AWG uses its normal authenticated handshake and never exposes a
  Winn-specific public probe.
- The two best warm circuits permitted by the selected mode.
- Small, bounded pools of ephemeral cryptographic material.

Defaults:

- Readiness TTL: 60 seconds.
- Warm-carrier maximum age: 10 minutes.
- Probe results expire faster than the readiness record and cannot outlive the
  manifest or credentials.
- Preparation sends no user traffic.
- Privacy cover traffic begins only after `Connect` selects an online privacy
  circuit.
- Mobile clients refresh on foreground and network change; correctness does not
  depend on unrestricted background execution.

### Click-time budget

- **0–100 ms:** freeze the readiness snapshot, activate/confirm kill switch,
  choose candidates, and apply the pending AWG generation.
- **100–1,200 ms:** race the mode’s eligible prepared candidates.
- **From approximately 1,000 ms:** queue candidate-scoped DNS and canary probes
  on candidates whose encrypted packet path is ready.
- **By 2,400 ms:** require a fresh AWG handshake and authenticated
  bidirectional bytes on the winner.
- **By 2,800 ms:** require protected DNS and the tunnel-only canary for that same
  winner.
- **By 3,000 ms:** publish `online` or fully tear down and publish failure.

### Candidate-isolated verification

- Do not change system DNS until a winner satisfies every predicate.
- Do not use the host resolver or ordinary network as a fallback.
- Queue speculative probe packets only into a candidate’s encrypted tunnel
  path; do not transmit them in cleartext while its handshake is incomplete.
- Bind every probe request and response to attempt ID, candidate ID, session,
  AWG generation, manifest digest, random nonce, and short expiry.
- Discard all results from losing, replaced, expired, or migrated candidates.
- Once one candidate satisfies every predicate, cancel all losers and establish
  one persistent teardown owner for every materialized or late loser.
- Commit routes and protected DNS atomically for the verified winner without
  waiting for isolated, never-committed loser process cleanup. A loser may own
  only candidate-scoped verification routes, fail-closed policy, and leases;
  it must never own global default route or DNS state.
- Detached loser teardown retries until its postconditions pass. Its leases
  remain unavailable, and attempt/generation close joins the same idempotent
  owner. A missing teardown owner or a loser that can mutate committed policy
  remains a fail-closed attempt error.
- If commit fails, tear the attempt down rather than publishing `online`.
- Treat the candidate-work binding expiry as authority to prepare, verify, and
  commit only. A committed H3 carrier and its protected underlay use a separate
  trust-derived session expiry; neither may fall back to the short work bound.
- DirectAWG may recover from a lost initial initiation only by bounded,
  readiness-relative refresh of the exact peer/controller resource, with exact
  binding and PSK-digest verification. Recovery cannot create a second peer,
  interface, relay, policy resource, attempt identity, or reset the absolute
  three-second deadline.

Deadline teardown removes:

- Routes and DNS changes.
- Candidate and sidecar sockets/processes.
- Temporary firewall state.
- Pending credentials and prepared keys that were exposed to the attempt.
- Probe queues and cover timers.

## Performance implementation

- Use all available CPU cores through separate bounded control, crypto, packet,
  probe, and metrics worker pools.
- Reuse fixed-capacity buffers and use batched packet I/O where supported.
- Use `SO_REUSEPORT`, RSS/queue affinity, and measured CPU pinning on Linux
  nodes.
- Enable BBR only where supported and validate it against the baseline.
- Bound every queue, goroutine/task pool, KEM pool, replay cache, and cover
  buffer.
- Apply backpressure or fail closed rather than allowing unbounded memory.
- Do not use GPU acceleration unless measurement later proves a CPU
  cryptographic bottleneck that safely benefits from it. Network round trips
  are expected to dominate connection latency.

## Native metadata privacy

### Basic two-hop

Route:

`client → entry → exit → internet`

- Entry may know the client IP but not the public destination.
- Exit may know the public destination but not the client IP.
- Entry and exit receive independent one-time credentials.
- Entry replaces circuit identifiers with random, memory-only unlinkable IDs.
- No stable client certificate is presented to public relay listeners.
- Place entry and exit under different provider accounts and credentials where
  operationally practical.

Basic two-hop is scored at most 3/5 because timing and volume remain
correlatable.

### Private Relay traffic shaping

- Use bounded size buckets.
- Add cryptographically generated 0–20 ms jitter.
- Limit cover overhead to 10% of user bytes over a rolling measurement window.
- Never delay interactive traffic merely to fill an unbounded bucket.

### Maximum Privacy

- Encode traffic in fixed 1,024-byte cells.
- Use a bounded 20 ms shuffle window.
- Send one cover cell per second in each direction while connected.
- Continue a 30-second cover tail after user traffic stops, subject to an
  explicit Stop immediately cancelling it.
- Rotate circuits every 15 minutes with make-before-break overlap.
- Enforce hard bandwidth, memory, battery, and queue limits.
- Separate cover scheduling from user packet queues so cover cannot starve user
  traffic.

The 4/5 metadata score applies only against:

- The local ISP.
- The destination.
- One compromised relay.
- One non-colluding infrastructure provider.

It does not claim resistance to colluding entry and exit operators, a global
passive observer, endpoint compromise, or long-duration intersection attacks.

## Infrastructure

Initial private topology:

- `winn-control-atl`: Vultr controller, token issuer, and manifest signer.
- `winn-entry-nyc`: dedicated-CPU Vultr entry and stealth node.
- `winn-entry-mia`: secondary Vultr entry and censorship fallback.
- `winn-exit-chi`: UpCloud US-CHI1 Premium 4-core/8-GB Ubuntu 24.04 exit.
- AICORE Ubuntu 24.04: local load, fuzz, network impairment, active-probe, and
  DPI laboratory.

The initial $350 monthly cloud target is an optimization hypothesis, not a
fixed capacity assumption:

- Split the paid fleet between Vultr and UpCloud so entry and exit observations,
  billing, credentials, and failure domains remain separated.
- Tag every resource by provider, node role, phase, and experiment.
- Record compute, storage, egress, backup, public-IP, logging, artifact, and tax
  costs from the first deployment.
- Calculate daily burn, projected monthly burn, cost per 10,000 connections,
  cost per seven-day soak, and cost per transferred TB after 24 and 72 hours.
- Treat $350/month as the optimization target, $500/month as the initial
  measured operating envelope, and $1,000/month as the owner-authorized ceiling
  used only when evidence shows that added spend materially improves delivery
  time, geographic evidence, throughput, or reliability.
- Alert before an envelope is exceeded, but do not automatically terminate an
  active security, privacy, or soak test.
- Resize or remove idle resources at phase gates.

The pre-provisioning balance baseline captured on 2026-07-23 is €233.63
available at UpCloud and $255 credit at Vultr, with no experiment servers and
no current experiment charges. The UpCloud console also displayed €276.37 of
July ongoing/historical account usage; this must not be mistaken for current
Winn Protocol burn. Reconcile console balance, invoice usage, and resource
inventory before and after every paid phase.

Scale only when archived measurements show CPU, queue, packet-processing,
storage, bandwidth, geographic, or fault-domain saturation. Do not add GPU
instances without a demonstrated GPU-suitable bottleneck.

The controller and issuer may share the small initial host for engineering
tests, but their keys, processes, logs, and roles remain separated. Entry and
exit must not share one host in privacy acceptance tests.

## Isolated reference clients

Delivery order:

1. Linux daemon and CLI.
2. macOS daemon and CLI.
3. Android AAR and Kotlin application on the connected physical Samsung phone.
4. Windows service and CLI on the Galaxy Book5 Pro, with an ephemeral UpCloud
   Windows VM as fallback.
5. iOS XCFramework and Swift application on the attached physical iPhone.

Production Winn VPN application integration remains deferred.

### Android gate

For each Android application smoke test:

1. Run `adb uninstall org.winsvpn.app`.
2. Install the latest release APK from
   `build/app/outputs/flutter-apk/app-release.apk` where shared app logic is
   involved.
3. Launch it and inspect `adb logcat` for startup, VPN, AWG, carrier, and
   service errors.
4. Run the isolated reference protocol proof and remove temporary secrets and
   binaries afterward.

### iOS memory policy

- Do not design around an assumed fixed `NEPacketTunnelProvider` memory limit.
- Measure real resident memory, peak allocations, and termination behavior on
  the physical iPhone.
- Use bounded rings, small cryptographic pools, and streaming cell processing.
- Keep only non-sensitive preparation metadata in an App Group.
- Store reusable secrets in an appropriately access-controlled Keychain item
  and revalidate them inside the extension.
- Do not depend on the host application remaining alive.
- Core and Maximum Privacy must each pass their own physical-device memory and
  battery gates before being marked compatible.

### Early iOS Maximum Privacy feasibility spike

Run a disposable physical-iPhone spike as soon as WCF3 cell framing and privacy
constants freeze, in parallel with the Phase 1 Linux vertical slice. Do not wait
for the complete Phase 5 privacy implementation.

The connected physical iPhone is available. The initial 2026-07-23 preflight
found no suitable isolated signing setup, but the 2026-07-24 follow-up produced
and installed a signed experimental host plus `NEPacketTunnelProvider` using
only the isolated bundle IDs and App Group. The host launches on the physical
device; the first Apple VPN-configuration consent remains an explicit
user-controlled gate and must not be automated or inferred. No physical
memory, battery, cover, or rotation result may be claimed until that consent is
granted and the device-generated evidence is collected and verified. Do not
substitute a simulator, typecheck, signed-build, installation, or launch result
for this physical-device gate.

The spike contains only a minimal `NEPacketTunnelProvider` data path with:

- Preallocated 1,024-byte cell rings and streaming encode/decode.
- The 20 ms bounded shuffle window.
- One synthetic cover cell per second in each direction.
- The 30-second cover tail.
- Circuit-rotation allocation behavior.
- Low, medium, and saturated synthetic packet profiles.

Exercise Wi-Fi, cellular, foreground, screen-locked, sleep/wake, thermal
pressure, and Low Power Mode. Record average/peak extension memory, allocation
growth, CPU, wakeups, battery relative to Core, packet backlog, latency,
suspension recovery, and any Jetsam or extension termination.

The spike passes only with no termination, bounded memory without an upward
trend, adequate measured memory headroom for AWG and hybrid cryptography, and
an incremental energy cost compatible with the Efficiency 4/5 gate. A failure
forces an early streaming/ring/pool redesign; it must not silently weaken cell,
mixing, or cover parameters.

## Measurement harness

Build this before new feature breadth. Store results append-only with:

- Source commit/tree digest and build artifact checksum.
- Protocol, manifest, carrier, sidecar, and configuration versions.
- Platform, OS, device, CPU, memory, and power state.
- Client/server region and infrastructure provider.
- Mode, carrier candidates, warm/cold readiness, RTT, loss, bandwidth, NAT, IP
  family, and censorship profile.
- Attempt timeline and each predicate timestamp.
- Exact success or failure code.
- Throughput, latency, packet loss, CPU, memory, battery, cover overhead, and
  reconnect measurements.
- Leak, DPI, active-probe, and metadata-correlation results.

The harness provides:

- p50/p95/p99 connection timing per mode and readiness class.
- Throughput comparison against the same-host raw AWG baseline.
- DNS, IPv4, IPv6, and WebRTC leak assertions.
- Network-change, NAT-rebind, sleep/wake, captive-portal, and outage injection.
- Passive-DPI and active-probe replay rigs on AICORE.
- Privacy traffic traces suitable for correlation testing.

Failed measurements are retained. No test result or scoring rule may be removed
merely to improve a score.

Every completed operation, including preparation, connection, trust, health,
and teardown failure, enters the authenticated attempt chain. An abort that
cannot produce a complete trustworthy denominator creates an immutable
exclusion and matrix-level invalidation record; that matrix ID can never be
resumed or retried into a pass.

The Phase 1 v2 schedule randomizes independently recreated 100-attempt batches.
For the 1.5-second latency threshold, each cell takes the larger of the exact
one-sided binomial exceedance upper bound and the one-sided t upper bound over
batch exceedance proportions. Formal verification requires all 100 batches per
cell, zero security failures, no invalidation/exclusion records, and the exact
frozen schedule, source, artifacts, qdisc evidence, and diagnostic-off
configuration.

The local measurement record uses a locked, append-only, HMAC-chained log plus
a separately authenticated high-water anchor. Missing records, single-file
truncation, duplicate attempt IDs, unknown failure codes, short writes, or
ambiguous durability poison the writer and fail closed. Coordinated rollback of
both local files remains possible to an attacker that controls the host, so
acceptance runs must additionally pin anchor digests off-host with two-provider
separation or an equivalent hardware-backed monotonic checkpoint.

## Delivery phases and gates

### Phase 0 — Freeze, harness, and records

- Freeze `winn/3`, manifest v2, WCF3, public API, threat models, score rubric,
  and cross-platform vectors.
- Build the measurement/result harness and network impairment profiles.
- Start the invention log and prior-art matrix immediately.
- Scaffold nightly connection cycles and the seven-day soak runner.
- Implement provider-tagged Vultr/UpCloud cost collection and burn projections
  before creating the full paid fleet.

Gate: frozen schemas/vectors round-trip and negative tests pass; the harness
records immutable success and failure results.

### Phase 1 — Linux vertical slice

- Implement the production raw-AWG adapter.
- Adapt H3 to the common interface.
- Implement `Prepare`, readiness, state/events, candidate racing,
  candidate-isolated verification, teardown, and `auto`.
- Use prepared live H3 and normal authenticated handshakes; keep 0-RTT disabled.
- In parallel, run the disposable physical-iPhone Maximum Privacy feasibility
  spike and feed its measured limits into the bounded data-path design.

Prelaunch screen: after the last Auto source change, the envelope-edge profile
must pass 1,000 warm plus 1,000 cold attempts in ten independently recreated
100-attempt batches per readiness. It requires zero availability/security
failures and uses the same archive/provenance/qdisc/schedule and cluster-aware
checks with the finite-sample t critical value. This is explicitly
non-promotional and cannot substitute for the formal gate.

Gate: on Linux, each of the four frozen network profiles completes 10,000 warm
plus 10,000 cold Auto attempts (80,000 total) with the frozen percentile,
individual-deadline, availability, security, and cluster-aware limits; direct
throughput reaches at least 90% of the same-host AWG baseline; and the full
dual-stack leak suite reports zero leaks. The phase cannot close with an
unresolved physical-iOS feasibility failure or without 24/72-hour projected
Vultr/UpCloud burn data.

### Phase 2 — Carrier breadth, stealth, and mobility

- Adapt H2 fallback and existing migration/handoff behavior.
- Add REALITY/XHTTP and WebSocket/TLS.
- Add `fast` and `stealth`.
- Implement regional camouflage policy and active-probe defenses.

Gate: all three modes pass timing, failover, passive-DPI, active-probe, and mode
non-downgrade tests. No real-country bypass claim is made from laboratory data.

### Phase 3 — Basic two-hop

- Implement native entry/exit roles and end-to-end exit authentication.
- Add independent credentials, identifier relabeling, and `private-relay`.
- Deploy entry and exit on separated provider accounts.

Gate: no single relay or provider can observe both client IP and destination in
the declared model; timing correlation is documented and metadata remains
capped at 3/5.

### Phase 4 — Cross-platform Core

- Port the common core to macOS, Android, Windows, and iOS.
- Keep identical protocol vectors, reason codes, and lifecycle behavior.
- Complete the required physical Android and iPhone gates.

Gate: every reference platform passes the Core lifecycle, leak, failure,
mobility, and three-second tests appropriate to its available network
interfaces.

### Phase 5 — Required privacy hardening

- Implement fixed cells, bounded mixing, jitter, cover budgets/tails, rotation,
  and `maximum-privacy`.
- Add traffic-correlation, resource-exhaustion, battery, and long-duration
  privacy tests.
- Port the bounded privacy data path to every reference platform that will
  count toward compatibility.

Gate: the declared metadata adversary tests pass, resource limits hold, and the
metadata score becomes eligible for 4/5. The overall Winn goal cannot complete
before this gate.

### Phase 6 — Full evidence package

- Run the complete connection, failover, soak, scale, privacy, DPI, leak,
  battery, and fault suite.
- Update the dated competitor scorecard from measured results.
- Package protocol/specification records, test vectors, build provenance,
  invention log, prior-art matrix, design alternatives, and known limitations.
- Prepare a private patent-counsel handoff.

Gate: every claimed score is traceable to archived evidence and every failure or
limitation remains disclosed in the private report.

## Verification matrix

- 10,000 warm and cold connection cycles per mode.
- p50/p95/p99 timing under every declared network envelope.
- Wi-Fi, Ethernet, cellular, NAT64, IPv4, IPv6, NAT rebinding, sleep/wake,
  captive portal, UDP block, TCP restriction, DNS interference, route change,
  process restart, and total outage.
- 1,000 make-before-break failovers.
- Continuous seven-day soak beginning when the Phase 1 vertical slice is stable.
- Throughput, latency, loss, CPU, memory, queue, battery, and cover-overhead
  budgets.
- Passive DPI and active probing for every camouflage carrier.
- DNS, IPv4, IPv6, and WebRTC leak tests with zero-leak acceptance.
- Downgrade, replay, token reuse, exhaustion, expiry, revocation, wrong suite,
  missing ECH, manifest equivocation, checkpoint rollback, and sidecar
  substitution negatives.
- Entry/exit separation, credential unlinkability, fixed-cell invariants, cover
  bounds, mix-window bounds, rotation, and correlation tests.
- Cross-platform byte-for-byte protocol vectors.
- Independent real in-region vantage tests before any named-country
  circumvention claim.

## Score gates

| Category | Minimum evidence before publishing Winn score |
|---|---|
| Throughput 5 | Fast mode at least 90% of AWG baseline plus measured multi-core scaling |
| Connection speed 5 | 10,000 cycles per mode with p99 at or below 3 seconds in the declared envelope |
| Reliability 5 | 1,000 failovers, seven-day soak, bounded resources, and fault recovery |
| Mobility 5 | Wi-Fi/cellular/Ethernet changes, sleep/wake, NAT rebinding, IPv4/IPv6, and NAT64 |
| Stealth 5 | Two structurally distinct camouflage carriers pass passive and active probes |
| Censorship bypass 5 | UDP, IP/DNS, TLS-fingerprint, SNI/ALPN, and representative DPI tests plus appropriately labeled real-vantage evidence |
| Compatibility 4 | Linux, macOS, Android, iOS, and Windows pass shared vectors and required physical gates |
| Efficiency 4 | Desktop/mobile CPU, memory, queue, battery, and cover budgets pass |
| Post-quantum resistance 5 | X25519 plus ML-KEM-768, ML-DSA, mandatory ECH, strict downgrade, expiry/revocation, and vectors pass |
| Metadata anonymity 4 | Two-hop separation, independent credentials, fixed cells, mixing, jitter, cover, rotation, and declared adversary tests pass |

## Confidentiality and patent records

- Keep source, cloud hosts, protocol details, scorecards, demonstrations, and
  test endpoints private until patent counsel approves disclosure.
- Do not public-push the experimental folder before that approval.
- Record dates, contributors, alternatives, failed approaches, prior art, and
  independently developed mechanisms throughout implementation.
- Describe potential inventions as candidate hypotheses for counsel, not as
  patentable conclusions.
- Candidate combinations to document include adaptive carrier preparation and
  racing, deterministic verified-or-fail connection deadlines, hybrid
  post-quantum AWG rekeying, candidate-isolated verification, and adaptive
  split-trust privacy behavior.
- Do not precommit to open-source publication, licensing, or public release in
  this implementation plan.

Patentability, novelty, non-obviousness, and freedom to operate require
qualified legal analysis. Successful engineering and private documentation do
not guarantee a patent.
