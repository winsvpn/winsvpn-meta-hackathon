# Winn Protocol v3 — Private Invention Log

**Confidential engineering record — not a patent application, legal opinion,
inventorship determination, or novelty conclusion.**

This file records when concrete Winn concepts became specific enough to
implement and test. Keep it private, append new entries rather than rewriting
history, and have patent counsel determine inventorship, claim scope, prior art,
ownership, export issues, and filing strategy.

## Handling rules

- Do not publish, push to a public repository, demo publicly, offer for sale,
  or give an unrestricted copy to another person before patent-counsel review.
- Record every external disclosure with recipient, date/time, exact material,
  confidentiality terms, and purpose.
- Identify the human who conceived each claimed feature. AI systems used for
  drafting, review, code generation, or testing are tools; this log does not
  decide who legally qualifies as an inventor.
- Never label a borrowed, standardized, open-source, or vendor-described
  feature as Winn’s invention. Record it as a known element and cite its source.
- Preserve source snapshots, test evidence, diagrams, failures, and alternative
  embodiments. A provisional filing only helps later-claimed subject matter to
  the extent the filing actually supports it.

Official filing/confidentiality references:

- USPTO provisional application guidance:
  https://www.uspto.gov/patents/basics/apply/provisional-application
- USPTO international filing considerations:
  https://www.uspto.gov/patents/basics/international-protection/filing-patents-abroad
- WIPO patent FAQ on pre-filing public disclosure:
  https://www.wipo.int/en/web/patents/faq_patents
- WIPO PCT prior-art guidance:
  https://www.wipo.int/en/web/pct-system/texts/ispe/11_01

## Disclosure register

| Date | Recipient/location | Material | Confidentiality | Status |
|---|---|---|---|---|
| 2026-07-23 | Private local Codex workspace and owner-authenticated Codex task | Plans, comparison, source, tests, and this log | Intended private; provider terms and counsel review not evaluated here | No public disclosure intentionally made |
| 2026-07-23 | Owner-authenticated UpCloud and Vultr consoles | Resource-price/balance inspection only | Account sessions | No Winn source or protocol disclosure sent |
| 2026-07-23 | Private AICORE host at SSH alias `aicore-lab-host` | Official AWG dependencies and the isolated AWG E2E test | Owner-controlled machine | No public service or endpoint created |
| 2026-07-24 | Private AICORE, Vultr/Atlanta, and UpCloud/Chicago owner-controlled hosts | Source-bound live-prepared H3 test artifact on AICORE; encrypted evidence-archive pins only on provider nodes | Owner-controlled SSH accounts; provider confidentiality terms not evaluated here | No public endpoint or intentional public disclosure created |

Add any human recipient, public use, repository visibility change, conference,
investor conversation, sale/offer, beta, or externally reachable server before
the next milestone.

## Known elements that are not claimed as Winn inventions

- WireGuard/AmneziaWG-style encrypted UDP data plane, handshake status,
  preshared keys, roaming, and AWG traffic obfuscation.
- X25519, ML-KEM-768, ML-DSA, TLS 1.3, ECH, QUIC, HTTP/3 CONNECT-UDP,
  HTTP/2, WebSocket/TLS, Xray REALITY/XHTTP, blind tokens, transparency logs,
  fixed-size traffic cells, cover traffic, mix delays, and two-hop VPN routing.
- Candidate racing, Happy Eyeballs-style selection, prepared connections,
  make-before-break, kill switches, protected DNS, route transactions, replay
  windows, append-only authenticated logs, and cloud-cost projections.
- Features publicly associated with DAITA, Hydra, Stealth, Chameleon, Lightway,
  and Nym-style anonymous networking as summarized in the private competitor
  scorecard. Those sources must be searched in depth before claim drafting.

The use of these ingredients can be lawful and technically valuable without
being novel. Potential claims, if any, must identify a new and non-obvious
system or method rather than a shopping list of known features.

## Entry INV-001 — Trust-bound verified-online race with fail-closed commit

**First reduced to executable form:** 2026-07-23  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex and external-model review  
**Evidence:** `internal/connectivity`, `internal/directawg`,
`internal/measurement`, their race tests, and
`WINN_PROTOCOL_V3_IMPLEMENTATION_PLAN.md`

Problem:

A VPN UI can report “connected” after only a socket or carrier handshake even
though the intended manifest, key generation, DNS path, inner tunnel, routing,
or privacy mode is not actually active. Racing candidates can also leak state
or commit the wrong route if losers and winners share mutable trust/context.

Potential Winn-specific combination to investigate:

1. Snapshot one complete trust tuple at click time: mode, manifest digest and
   expiry, PSK generation and expiry, session, sequence epoch, candidate/node
   identities, credential state, and absolute deadline.
2. Derive an immutable attempt binding and require every candidate-local
   handshake, DNS, canary, counter, and frame context to match it.
3. Race heterogeneous carriers while speculative DNS/canary checks remain
   candidate isolated.
4. Cancel, join, and tear down every loser before the winning route/DNS
   transaction may commit.
5. Publish Online only after an authenticated AWG handshake, bidirectional
   movement, protected DNS, a binding-aware tunnel canary, and atomic commit.
6. Continue monitoring the committed carrier; terminal health loss revokes
   Online and synchronously rolls back routes/DNS while keeping or engaging the
   kill switch.
7. Produce a stable attempt ID and immutable failure record even when trust
   validation or the three-second deadline fails before any candidate dials.

Alternative embodiments to preserve:

- Direct AWG, H3, H2, camouflage sidecar, basic two-hop, or fixed-cell privacy
  candidate.
- Sequential fallback versus concurrent race.
- Platform route transaction, network extension, Android protected socket,
  Linux mark/table, or userspace tunnel.
- Hardware/off-host monotonic evidence anchor.

Novelty status:

**Unsearched and unproven.** Each individual step has close analogues in VPN,
transport-racing, transactional networking, and zero-trust systems. Counsel
should evaluate whether the exact binding/ordering/health/evidence combination
is both new and non-obvious.

## Entry INV-002 — Manifest-enforced anonymity floor for two-hop modes

**First reduced to schema/tests:** 2026-07-23  
**Human conceiver(s):** owner/counsel must complete  
**Evidence:** `internal/gatewaymanifest/manifest_v2.go`,
`internal/privacytoken`, `internal/transparency`, and WCF3 code/tests

Problem:

A client-selected “two-hop” path can be nominally two nodes while remaining one
operator/provider/credential observer, or it can silently fall back from a
traffic-analysis-resistant mode to a timing-visible relay.

Potential Winn-specific combination to investigate:

- A signed, transparency-pinned circuit object binds mode, entry and exit node,
  transport, role, operator, infrastructure provider, issuer/key, and
  independent credential domain.
- Validation rejects same-node, same-operator, same-provider, same-key, or
  credential-domain reuse for an anonymity-scored circuit.
- The mode contract binds the circuit to either native two-hop or exact
  fixed-cell/replay/cover parameters; a client cannot call basic two-hop
  “Maximum Privacy.”
- Connection evidence records the exact circuit/trust digest and refuses to
  score metadata anonymity when the separation or privacy predicate is absent.

Novelty status:

**Unsearched and unproven.** Multi-hop separation, blind credentials, fixed
cells, cover traffic, and transparency are known. The possible focus is
machine-enforced coupling of topology independence, credential independence,
mode semantics, and evidence—not the underlying primitives.

## Entry INV-003 — Privacy cell context tied to connection trust epoch

**First reduced to executable form:** 2026-07-23  
**Human conceiver(s):** owner/counsel must complete  
**Evidence:** `internal/wcf3` and
`spikes/ios_maximum_privacy/PrivacyCore`

Potential Winn-specific combination to investigate:

- Every fixed-size privacy cell binds a compact context derived from attempt,
  profile, mode, manifest, candidate/circuit, node, PSK generation, sequence
  epoch, session, nonce, and expiry.
- Independent direction/epoch replay windows reject duplicates and old cells,
  and the sequence allocator fails before wrap.
- A bounded 0–20 ms shaper, continuous cover option, 30-second tail option, and
  two preallocated rotation pools operate without weakening the same context.
- The implementation treats physical mobile memory/energy feasibility as a
  mode-availability gate rather than silently changing cell/cover parameters.

Novelty status:

**Unsearched and likely crowded.** Fixed cells, replay windows, padding, cover,
mix delays, and key epochs are established fields. Search onion-routing,
mixnet, VPN, QUIC, IPsec, and traffic-flow-confidentiality patents before
claiming this area.

## Entry INV-004 — No custom-probe direct AWG readiness

**First reduced to executable form:** 2026-07-23  
**Evidence:** `internal/directawg` and `scripts/aicore_awg_e2e.sh`

This is primarily a security/engineering decision, not presently identified as
an invention. Winn does not add an unauthenticated or separately keyed public
UDP probe. It derives readiness from a fresh candidate-isolated authenticated
AWG session, signed peer/endpoint, current PSK generation, counter movement,
protected DNS, and an inner canary. Preserve it as defensive implementation
evidence, but do not assume patentability.

## Entry INV-005 — Credential-safe authenticated carrier preparation joined to click binding

**First reduced to executable form and privileged evidence:** 2026-07-24  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex and external-model review  
**Evidence:** `internal/carrier/h3.go`, `internal/h3candidate/prepared.go`,
`internal/linuxauto`, `internal/autoconnect`, and
`evidence/h3-e2e-live-prepared-20260724/`

Problem:

A VPN can pre-open a transport to reduce click latency, but authenticating too
early can bind the wrong session, expose or consume a one-time anonymous
credential before user intent, enable replay through 0-RTT, or let a stale
transport outlive the trust/readiness state it purports to accelerate.

Potential Winn-specific ordered combination to investigate:

1. Establish a protected fixed-IP QUIC/TLS path under signed endpoint, ECH,
   hybrid-suite, interface, and mark constraints without a click binding or
   click credential.
2. Before publication as warm, issue a normal independently authenticated
   CONNECT-UDP and carrier-datagram proof, then close only that logical CONNECT
   while preserving its already-validated HTTP/3 connection.
3. Retain the path and its protected underlay as one generation-owned,
   transport-profile-bound, single-use resource with a readiness expiry.
4. On click, atomically validate/reserve the prepared path before consulting a
   one-time anonymous credential source, preventing duplicate/stale clicks from
   burning credentials.
5. Claim the previously unbound protected underlay with an immutable
   click-time trust/session/epoch/candidate binding whose expiry cannot exceed
   the authenticated readiness lifetime.
6. Send a distinct non-0-RTT authenticated CONNECT on the retained HTTP/3
   connection, then require fresh inner-tunnel, bidirectional, protected-DNS,
   canary, and atomic-commit predicates within one click deadline.
7. Pin all preparation ownership for the online lifetime and tear down in
   selected tunnel → click lease → prepared-generation order.

Alternative embodiments to preserve:

- Identity authentication for private diagnostic fixtures versus blind,
  one-time anonymous credentials for production.
- H3 CONNECT-UDP versus another multiplexed carrier that can close a
  preparation stream while retaining a validated transport.
- One prepared candidate versus a heterogeneous prepared race.
- Mobile protected sockets, Linux interface/mark policy, or a platform network
  extension enforcing the same binding and ownership semantics.

Novelty status:

**Unsearched and unproven.** Connection prewarming, authenticated health
checks, single-use tokens, QUIC connection reuse, and candidate racing are
known individually. Counsel should search whether the exact two-authentication
ordering, pre-credential reservation, trust-expiry coupling, and online
ownership sequence is new and non-obvious as a combination.

## Entry INV-006 — Anchor-barrier ordering for heterogeneous speculative VPN preparation

**First reduced to executable form and privileged evidence:** 2026-07-24  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex  
**Evidence:** `internal/preparation/production_factory.go`,
`internal/preparation/production_factory_test.go`,
`internal/linuxauto`, and
`evidence/auto-e2e-production-20260724/`

Problem:

A heterogeneous VPN race may prepare a direct raw-UDP candidate and a
multiplexed carrier concurrently. If both depend on one fail-closed underlay
policy, the direct path can inspect or authorize a socket before the warm
carrier has installed and verified the persistent policy anchor. Serializing
all preparation avoids the race but sacrifices background latency.

Potential Winn-specific ordered combination to investigate:

1. Determine from a verified signed deployment that the selected preparation
   generation contains both DirectAWG and an H3 carrier sharing one platform
   fail-closed underlay contract.
2. Let both candidate preparations begin and pin their exact PSK/credential
   state concurrently.
3. Require the H3 path to install, read back, and publish the persistent policy
   anchor before Direct can request its pre-dial underlay authorization.
4. Release Direct immediately after anchor publication so the expensive live
   Direct probe and H3/TLS preparation continue concurrently.
5. Bind the barrier result to the same manifest sequence, trust expiry,
   interface, direct mark, H3 mark, and candidate-generation ownership.
6. If anchor publication fails or the shared preparation context is canceled,
   prevent Direct from crossing the barrier and retire all partially acquired
   leases in reverse ownership order.
7. Keep the H3-owned anchor live through the complete speculative race and
   selected Online lifetime, removing it only after both carrier and candidate
   resources are closed.

Privileged evidence:

Eleven AICORE runs passed with zero failures. All retained concurrent
preparation, two anonymous H3 authentications/redemptions, a real DirectAWG
winner, and byte-identical host state after teardown. A race-enabled regression
repeated twenty times and proved Direct authorization could not occur before
anchor publication.

Novelty status:

**Unsearched and likely narrow.** Barriers, dependency graphs, fail-closed
firewalls, and speculative connection racing are established techniques.
Counsel should investigate only whether the exact verified-trust binding,
heterogeneous preparation ordering, credential ownership, and loser teardown
combination is new and non-obvious. Do not claim the generic barrier pattern.

## Entry INV-007 — Non-resettable preparation-to-click deadline bound into candidate authority

**First reduced to executable form and privileged evidence:** 2026-07-24  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex  
**Evidence:** `internal/autoconnect/attempt.go`,
`internal/connectivity/coordinator.go`,
`internal/measurement/from_result.go`,
`cmd/winn-auto-e2e`,
`evidence/phase1-auto-preflight-20260724/`, and
`evidence/phase1-auto-shaped-preflight-20260724/`

Problem:

A VPN can claim a three-second cold connection while timing preparation and
click separately, or while canceling preparation at an earlier parent
deadline but issuing candidate bindings whose authenticated expiry still uses
a newly reset click/readiness lifetime. That makes the score misleading and
can leave an authority token valid longer than the operation that justified
it.

Potential Winn-specific ordered combination to investigate:

1. Select a signed deployment, candidate set, PSK generation, credential
   classes, and fail-closed policy before beginning the cold score.
2. Create one absolute parent deadline immediately before verified assembly.
3. Perform manifest-bound assembly, live carrier proof, credential
   reservation, policy anchoring, and trust-state commit under that same
   parent context.
4. Pass the unchanged parent context into the single-use click attempt.
5. At click, compute the effective deadline as the earlier of the parent
   deadline and the ordinary click ceiling rather than granting a fresh
   interval.
6. Include the resulting remaining duration in the request fingerprint and
   cap every candidate binding's authenticated `ExpiresAt` by the same
   effective deadline, even if manifest, PSK, credential, and readiness
   lifetimes are longer.
7. Preserve the coordinator's authoritative result, but rebase every nonzero
   predicate timestamp onto the earlier cold boundary in a tamper-evident
   measurement record.
8. Retain warm scoring as a distinct class whose boundary begins only after a
   separately fresh generation is fully prepared; never synthesize warm/cold
   labels from a reused readiness object.

Privileged evidence:

Two baseline true-cold generations reached verified Online in 215.792 and
215.875 ms. Two frozen 250 ms/3%/10 Mbps edge cold generations reached Online
in 1.392731 and 1.392914 seconds. All used fresh signed assembly, live
DirectAWG/H3 preparation, blind credentials, durable redemption, four
protected predicates, exact HMAC measurement records, and bounded cleanup.

Novelty status:

**Unsearched and likely narrow.** Absolute deadlines, context propagation,
token expiry, connection timing, and tamper-evident logs are individually
well known. Counsel should search whether binding the same non-resettable
preparation-to-click deadline into verified deployment assembly, request
fingerprinting, anonymous credential ownership, candidate authority expiry,
and rebased predicate evidence is new and non-obvious as an ordered
combination. Do not claim the generic idea of an end-to-end timeout.

## Prior-art work queue

1. Search patents and non-patent literature for VPN candidate racing with
   post-handshake DNS/canary predicates and atomic route commit.
2. Search transaction/consensus/network-control patents for loser teardown
   ordering and post-commit health rollback.
3. Search multi-hop VPN/onion/mixnet systems for signed topology/provider/
   credential-separation constraints.
4. Search traffic-flow-confidentiality systems for fixed cells bound to trust
   epochs and bounded mobile rotation pools.
5. Map every proposed claim element to an earliest-known public source and
   identify what, if anything, remains distinct as an ordered combination.
6. Have counsel decide whether to file a complete provisional before any public
   test or disclosure; international rights can be affected by pre-filing
   disclosure even where a U.S. grace period may exist.

## Evidence index at this snapshot

- `WINN_PROTOCOL_V3_IMPLEMENTATION_PLAN.md`
- `WINN_PROTOCOL_V3_COMPETITOR_SCORECARD_2026-07-23.md`
- `WINN_PROTOCOL_V3_CONTINUATION_LOG.md`
- `internal/connectivity`
- `internal/directawg`
- `internal/gatewaymanifest`
- `internal/measurement`
- `internal/privacytoken`
- `internal/transparency`
- `internal/wcf3`
- `spikes/ios_maximum_privacy`
- `scripts/aicore_awg_e2e.sh`
- `scripts/aicore_h3_e2e.sh`
- `scripts/aicore_auto_e2e.sh`
- `scripts/aicore_phase1_auto_matrix.sh`
- `scripts/build_h3_e2e_linux.sh`
- `scripts/build_auto_e2e_linux.sh`
- `evidence/h3-e2e-live-prepared-20260724`
- `evidence/auto-e2e-production-20260724`
- `evidence/phase1-auto-preflight-20260724`
- `evidence/phase1-auto-shaped-preflight-20260724`
- `CLOUD_COST_BASELINE_2026-07-23.json`

Append the source tree/commit digest, artifact checksums, human contributor
statements, and counsel docket number when a private milestone is frozen.

## Entry INV-008 — Deadline-preserving candidate race with fail-closed bounded loser retirement

**First reduced to executable form and privileged evidence:** 2026-07-24  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex  
**Evidence:** `internal/connectivity/coordinator.go`,
`internal/connectivity/coordinator_test.go`,
`scripts/aicore_phase1_auto_matrix.sh`,
`/opt/winn-lab/matrices/phase1-auto-formal-0b7019d5-v3/failed/`,
and the private AICORE preflight archive whose SHA-256 is
`ba45b31198e5c29f2f4d15c977921f865984ea7adb69d000404ce415a5f68b64`

Problem:

A candidate-racing VPN can honor cancellation in its probes but still violate
the advertised connect-or-fail deadline by synchronously draining every losing
candidate and calling an unbounded `Close()`. Returning immediately without
retirement would meet latency only by risking a live losing tunnel, credential,
route, DNS, or fail-closed-policy resource. Treating an unreturned close as
success would also hide a security-relevant teardown failure.

Potential Winn-specific ordered combination to investigate:

1. Give every racing candidate the same authenticated, non-resettable
   connection deadline.
2. Cancel all losing candidate work immediately after a winner or terminal
   deadline.
3. Initiate close for every materialized losing connection and continue
   draining the bounded result channel.
4. Bound close, speculative-probe join, and loser-result drain with a separate,
   short cleanup grace that cannot reset the advertised connection deadline.
5. If cleanup completes, preserve the ordinary winner or deadline result.
6. If any candidate ignores cancellation, its close blocks, or its probes do
   not join within the grace, return an explicit fail-closed
   `teardown_failed` result instead of Online, an ordinary timeout, or an
   indefinitely blocked call.
7. Continue best-effort retirement in detached bounded ownership while
   invalidating the coordinator generation so late completion cannot publish
   Online.
8. Add an outer per-batch wall-clock ceiling to the evidence runner so an
   implementation defect is preserved as a failed batch rather than consuming
   test infrastructure indefinitely or being silently retried into a score.

Privileged evidence:

The earlier source-frozen matrix produced 20,141 successful measurement
records and then remained stuck for more than 35 minutes in the 142nd attempt
of a batch. Its incomplete pinned archive is retained with
`FAIL status=130` and SHA-256
`a94fe5d49dc2e3f0c0115510fe92d4fb41206b6289f8b2451c272a096b5fdea7`.
After implementing the bounded-retirement rule, a regression with a
deliberately blocked `Close()` returned bounded `teardown_failed`; race tests
passed; and a real AICORE preflight passed 500/500 with p99 84.027 ms and
complete cleanup.

Novelty status:

**Unsearched and likely narrow.** Timeouts, cancellation, racing connections,
asynchronous cleanup, and watchdogs are individually established techniques.
Counsel should investigate only whether the exact ordered combination of
authenticated candidate authority, mandatory loser retirement, separate
non-resetting cleanup grace, fail-closed result reclassification, late-result
generation invalidation, and tamper-evident failed-batch preservation is new
and non-obvious. Do not claim generic timeout or asynchronous-close concepts.

## Entry INV-009 — Deadline-bounded result with persistent staged-teardown ownership

**First reduced to executable form and privileged evidence:** 2026-07-24  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex  
**Evidence:** `internal/connectivity/coordinator.go`,
`internal/directawg/candidate.go`, `internal/directawg/linux_exec.go`,
`internal/h3candidate/connection.go`,
`internal/h3candidate/linux_awg_adapter.go`, their focused tests, and private
AICORE preflight archive SHA-256
`37c3ce786b03c68b053ae315511d9a2906d3670a3dda9cf126c72da11eaef76d`

Problem:

A connection API can meet a hard user-visible deadline by returning after a
short cleanup wait, yet still lose the last object capable of resuming a
partially completed route/DNS/interface/process rollback. Conversely, treating
the carrier outage that triggered cleanup as a teardown error can poison safe
reconnect even when rollback succeeded.

Potential Winn-specific ordered combination to investigate:

1. End candidate work early enough to reserve cleanup inside one
   non-resettable connection deadline.
2. Establish exactly one teardown owner before observing an expired cleanup
   context.
3. Return fail-closed `teardown_failed` if proof cannot arrive within the
   user-visible deadline, while retaining that exact owner after return.
4. Let retry-capable Direct-AWG/H3 wrappers preserve completed rollback stages
   and serialize all late-Commit, health, Stop, and abandon owners.
5. Retry unfinished staged teardown with capped exponential backoff until
   success, while poisoning the coordinator so new candidate generations
   cannot multiply state during recovery.
6. Report only rollback/postcondition errors through Close; deliver the
   original carrier/relay outage separately through the health channel.
7. When graceful process stop times out, escalate, wait for confirmed exit,
   and treat the proven postcondition as success so later lease-release stages
   can run.
8. Bind resulting evidence to the exact source/artifact and retain failed
   predecessor runs rather than splicing their successful measurements.

Privileged evidence:

Regressions prove ownership survives the caller deadline and three consecutive
transient teardown failures before completing on the fourth attempt. Real
process tests prove timeout escalation plus confirmed exit. Two independent
audits found no remaining P0/P1 lifecycle invalidator. The frozen AICORE source
then passed 500/500 authenticated production-Auto attempts with zero failures,
p99 84.974 ms, 1,000 one-time redemptions, and residue-free teardown.

Novelty status:

**Unsearched and likely narrow.** Retry loops, exponential backoff, process
supervision, staged rollback, health channels, and hard deadlines are
established techniques. Counsel should search only the exact ordered
combination of authenticated candidate authority, in-deadline proof,
post-return persistent teardown ownership, generation poisoning, operational
health/rollback error separation, and evidence-preserving promotion. Do not
claim generic retries, backoff, or process-kill semantics.

## Entry INV-010 — Signed server-terminated anonymous carrier preparation separated from data authorization

**First reduced to executable form and privileged evidence:** 2026-07-25  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex, with independent multi-model review  
**Evidence:** `internal/carrierauth/auth.go`, `internal/pqauth/pqauth.go`,
`internal/carrier/h3.go`, `internal/masque/conn.go`,
`internal/h3candidate/prepared.go`, their focused race/integration tests, and
private AICORE archive SHA-256 values
`43be1b19bf13f07dfcb4e019e5db0cea31a3ee55d609cb5ed09a66b12c2d8405`
and
`44b86bdd8759aa837b9afc99150b03ee0d34d162fc70cf00990b371f16c5b7a6`

Problem:

An authenticated H3 carrier can be prepared before selection, but opening its
backend data relay during preparation wastes server resources and creates
lifecycle ambiguity. Closing the preparation stream or QUIC connection from
the client is not a reliable server-side retirement signal under packet loss:
the final close can be lost, leaving an authenticated relay alive until a long
transport idle timeout. Reusing the same anonymous credential for click would
also turn the preparation authorization into a linkable multi-use handle.

Potential Winn-specific ordered combination to investigate:

1. Include a signed, domain-separated request purpose in the carrier
   authentication transcript.
2. Use `authenticate-only` during speculative preparation and consume a
   single-use anonymous credential while verifying the same transport,
   controller identity, manifest authority, ECH/TLS path, and response
   signature needed for candidate readiness.
3. Have the server return a signed authenticated response and terminate the
   request without opening or dialing an AWG backend data relay.
4. Require click to use a distinct freshly issued one-time credential with
   purpose `data`; never upgrade the preparation request or credential in
   place.
5. Keep full click-time MTU, live-tunnel, protected-DNS, and canary proofs
   mandatory and bound to the exact single-use connection attempt.
6. Audit authentication-only and data purposes separately, and require durable
   redemption count to equal their sum while data opens equal data closes.
7. Treat the expected simultaneous H3_NO_ERROR close race as idempotent, while
   preserving all non-normal relay closure errors.

Privileged evidence:

Server integration tests prove preparation consumes one credential and opens
zero backend sockets, while click consumes a fresh credential and opens exactly
one. Race suites passed 100 authenticated H3 integrations and repeated
preparation/hedge/close ownership tests. In the real 250 ms RTT, 3% loss,
10 Mbps AICORE checkpoint, 365 authentication-only requests plus 100 data
opens produced exactly 465 durable one-time redemptions, all 100 data opens
closed, carrier logs had no relay errors, and 200/200 Auto attempts completed
under 1.098 seconds.

Novelty status:

**Unsearched and likely narrow.** Purpose-bound signatures, single-use
credentials, pre-authentication, server-side request termination, and resource
accounting are individually established techniques. Counsel should investigate
only the ordered combination of anonymous one-time purpose separation,
controller-signed no-backend readiness, fresh data authorization, exact
attempt-bound click proofs, and convergence accounting as one VPN carrier
preparation system. Do not claim generic pre-authentication, HTTP request
purposes, anonymous credentials, or server-initiated close concepts.

## Entry INV-011 — Dual-horizon candidate authority with same-resource handshake recovery

**First reduced to executable form and privileged evidence:** 2026-07-25  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex, following independent Opus/Fable review  
**Evidence:** `internal/connectivity`, `internal/directawg`,
`internal/h3candidate`, `internal/linuxauto`, their focused/race tests, private
AICORE archives whose SHA-256 values are
`889cad5e19f4f8f9c37ce8340bb88eb824857241b9fa4552d380aee211816940`
and
`2a49e4622859c03370ee643eeac91837b70b35322060384e6a87f1f96456c4d8`,
and current Auto source
`2c1b24174509c28cc437c347de4685cae45f373f4a087b4ae0630ca6b9237165`

Problem:

A hard-deadline candidate race needs short authority that prevents late
candidate work from committing after the user-visible outcome window. Reusing
that short authority as the lifetime of the committed tunnel causes a valid
winner to self-destruct immediately after connection. At the same time, the
underlying AWG implementation can suppress another initial handshake longer
than the complete Winn deadline, so ordinary initiation loss cannot be
recovered by waiting for the transport's default retry.

Potential Winn-specific ordered combination to investigate:

1. Bind all preparation, candidate work, validation, and commit to a
   single-use authenticated work authority whose expiry cannot exceed the
   non-resettable user-operation deadline.
2. Independently derive a longer committed-session authority from authenticated
   manifest, credential, underlay, and rotation trust bounds.
3. Allow only the commit transition for the exact work binding to exchange the
   short work authority for the independently bounded session authority; never
   extend candidate work or accept a rebind.
4. Enforce the session authority in both the carrier connection and protected
   underlay so neither silently falls back to the short work expiry.
5. If fresh-handshake proof is still absent after declared offsets, refresh
   the exact already-created peer/controller state rather than create a second
   peer, interface, relay, policy resource, or attempt identity.
6. Before each refresh, verify the exact binding and PSK digest, use temporary
   secret material only for the controller call, and preserve the original
   absolute deadline.
7. Begin recovery offsets only after controller/peer readiness, so local setup
   time cannot consume the loss-recovery schedule.
8. Retain authenticated negative evidence for blackout conditions that exceed
   the declared impairment model instead of converting them into later
   successful samples.

Privileged evidence:

A forced H3 winner remained healthy for a four-second hold that crossed the
former short work-expiry boundary, with verified Online at 1.052246 seconds.
In a separate edge-cold run, the first five outer DirectAWG writes were
deliberately discarded; the same candidate resource recovered and reached
verified Online in 944.678 milliseconds with complete protected-DNS, canary,
measurement, teardown, and residue checks. An 800 ms complete outer blackout
was retained as a clean negative diagnostic rather than counted as a pass.

Novelty status:

**Unsearched and likely narrow.** Capability lifetimes, session tickets,
deadlines, WireGuard peer reconfiguration, retry schedules, and PSK checks are
individually established techniques. Counsel should search only the exact
ordered combination of single-use deadline-bounded work authority,
commit-only exchange for independently bounded session authority,
cross-layer enforcement, same-resource peer refresh with secret/binding
verification, readiness-relative recovery timing, and evidence-preserving
negative classification. Do not claim generic expiry separation, retry,
WireGuard reconfiguration, or deadline concepts.

## 2026-07-25 evidence-lineage correction for INV-010 and INV-011

The source `2c1b2417…` and its privileged archives remain valid
source-specific evidence for the concepts recorded above, but they are not the
current implementation candidate. Later source identities are recorded in the
shared monitor and continuation log.

The first 100-attempt `0b3f3177…` staging batch also disproved an overly narrow
INV-010 accounting statement: a successfully redeemed/authenticated request
can encounter a later capacity, rate, backend, or response failure before it
becomes terminal `authenticate-only` or an opened data relay. Therefore,
durable redemption count must equal a distinct authentication-boundary audit
event, not necessarily `auth_only + open`. Terminal purpose events remain
subsets, and data `open == closed` remains separately mandatory. The failed
batch and correction are retained under:

```text
INVALID_sha256=37eec94abe7080c058838881dee5d04bebbff3c958c025ca74dbb6b79822c7f2
corrected_source=0b3cfb8a5983d9ccf428a44a14798b0da0c595063a638e48c2298dfb86b31d74
```

This is an evidence correction, not a new patentability conclusion.

## Entry INV-012 — Two-independent-provider resumable acceptance-evidence chain

**First reduced to executable form:** 2026-07-25  
**Human conceiver(s):** owner/counsel must complete  
**AI assistance used:** Codex plus independent model review  
**Evidence:** `internal/phase1anchor`, `cmd/winn-phase1-anchor-*`,
`scripts/aicore_phase1_auto_matrix.sh`,
`cmd/winn-phase1-matrix-verify`, private forced-command deployments on
independent Vultr and UpCloud accounts, and the integrated smoke named
`phase1-anchor-integrated-smoke-0b3cfb8a-v1`

Problem:

A long protocol acceptance run cannot safely rerun an already completed batch
when one external archive provider is temporarily unavailable: rerunning
selects a new sample after outcome observation. A purely local `.done` marker
is also replaceable by the measurement host and cannot prove the ordered
history to an independent verifier.

Potential Winn-specific ordered combination to investigate:

1. Freeze matrix/source/artifact/profile/schedule identity before attempt one.
2. Establish independently trusted provider-generated signing keys and
   sequence-zero genesis receipts on two separate provider accounts.
3. Bind each fixed-denominator batch to its exact schedule row, archive,
   evidence manifest, authenticated attempt log, and attempt-chain anchor.
4. Persist an immutable local `.pin-pending` request before remote submission.
5. Use a slot-derived idempotency key so an identical retry returns the same
   provider receipt, while any different request at that ordinal is rejected.
6. Require both independently signed previous-hash/sequence receipts before
   local `.done`; a one-provider outage retries only the identical pending
   request and never reruns protocol attempts.
7. Build an ordered aggregate over requests, both receipt chains, and local
   batch records; require two final post-batch seals before completion.
8. Verify offline using provider identities and keys supplied outside the
   evidence root, refusing gaps, forks, pending state, identical provider keys,
   changed evidence, or locally substituted trust roots.

Novelty status:

**Unsearched and likely narrow.** Transparency logs, timestamp authorities,
append-only ledgers, Ed25519 signatures, hash chains, idempotency keys,
two-party notarization, and resumable jobs are established techniques. Counsel
should investigate only the ordered use of dual independent monotonic receipt
chains to preserve the denominator of a long VPN acceptance experiment across
partial provider outage, with pre-`.done` exact pending state and a dual-signed
terminal aggregate. Do not claim generic ledgers, signatures, timestamping,
hash chains, or resumable uploads.
