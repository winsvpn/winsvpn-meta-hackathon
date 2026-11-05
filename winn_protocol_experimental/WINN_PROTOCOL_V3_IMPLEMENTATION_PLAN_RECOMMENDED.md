# Winn Protocol v3 — External Review Record (SUPERSEDED)

Status: **superseded review history. Not an implementation plan. Do not build from this file.**
Review date: 2026-07-23
Reviewer: external (Claude/Opus), at owner request
Authoritative plan: [`WINN_PROTOCOL_V3_IMPLEMENTATION_PLAN.md`](WINN_PROTOCOL_V3_IMPLEMENTATION_PLAN.md)

This file previously contained a competing "recommended" plan. That plan has
been fully superseded by the authoritative implementation plan, which
incorporated the review's substantive points and improved on several of them.
This record is retained only so the reasoning and its outcome stay traceable.

## What the review recommended, and what happened

| Review recommendation | Outcome in the authoritative plan |
|---|---|
| Reframe v3 as an extension of v2, not a rewrite | **Adopted**, with a per-capability v2 reuse table |
| Build the measurement harness before feature breadth | **Adopted** as Phase 0, with a fuller append-only result schema |
| Prove one vertical slice (Linux, one mode) before breadth | **Adopted** as Phase 1 with a concrete numeric gate |
| Add an explicit active-probing threat model | **Adopted** and expanded |
| Treat REALITY decoy/SNI selection as first-class design, not config | **Adopted**, and better framed as signed *regional operational policy* |
| Start the soak early; make cycle runs continuous, not a final event | **Adopted** (Phase 0 scaffolding, soak from Phase 1 stability) |
| State plainly that lab DPI ≠ proof of in-country circumvention | **Adopted**, plus a real-vantage requirement before any named-country claim |
| Pipeline the click-time DNS/canary verification | **Adopted but hardened** — see "corrections" below |
| Enable QUIC 0-RTT for carrier resumption | **Rejected, correctly** — see "corrections" below |
| Design around an assumed iOS extension memory ceiling | **Rejected, correctly** — see "corrections" below |
| Descope Maximum Privacy / mixnet out of v3 | **Rejected** — resolved better by sequencing and gating instead |

## Where the authoritative plan corrected the review

These are recorded because the corrections are more valuable than the
recommendations that survived.

1. **iOS memory.** The review asserted a specific `NEPacketTunnelProvider`
   memory ceiling from recollection and told the team to design a "lean profile"
   around it. The plan instead requires *measuring* real resident memory, peak
   allocations, and termination behavior on the physical device. Designing
   against an unverified constant would either over-constrain the design or fail
   late. The plan is right.

2. **QUIC 0-RTT.** The review recommended enabling 0-RTT for carrier resumption
   as a latency lever on the three-second budget. The plan disables it on the
   Core path behind a seven-condition security gate, and identifies a risk the
   review missed entirely: **TLS session tickets and QUIC resumption are a
   metadata-linkability vector**, not merely a replay risk. For a privacy VPN
   that consideration outranks the latency gain. The plan is right.

3. **Candidate-isolated verification.** The review proposed running DNS and
   canary probes speculatively, concurrent with the handshake tail. The plan
   accepts the concurrency but closes a real leak hole in the naive form:
   system DNS is never touched until a winner satisfies every predicate, the
   host resolver is never a fallback, speculative probes are queued *only* into
   a candidate's encrypted path (never transmitted in cleartext during an
   incomplete handshake), every probe binds attempt/candidate/session/generation/
   manifest/nonce/expiry, losing-candidate results are discarded, and the route
   and DNS commit is atomic. The plan is right.

## The one substantive disagreement, and why the plan's resolution is better

The review argued for cutting Maximum Privacy (fixed cells, bounded mixing,
cover traffic) from v3 on the grounds that it is the largest timeline and audit
risk and competes on the single axis where purpose-built mixnets already lead.

The plan keeps it as a required Phase 5 and a completion condition. That is the
better resolution: metadata anonymity at 4/5 is a stated product goal in the
project's own scorecard, so cutting it means not building the intended product.
The review's actual concern was schedule risk, and the plan addresses that
directly instead of by descoping — sequencing it fifth of six, capping basic
two-hop at 3/5 until the full suite passes, and bounding the 4/5 claim to a
declared adversary model that explicitly disclaims colluding entry+exit
operators and global passive observers.

## Material additions the review did not identify

- **Mode non-downgrade as a security property** — Stealth may not fall back to
  raw UDP; Maximum Privacy may not fall back to single-hop. A silent fallback
  that weakens a privacy mode is a vulnerability class, not a UX detail. This is
  the most important item the review missed.
- Authenticated, rate-limited reachability probe so arbitrary UDP responses
  cannot mark an endpoint ready.
- Sidecar process identity / configuration digest / lifecycle binding, and
  fail-closed behavior that cannot bypass the kill switch.
- `stopping`/`stopped` states, an explicit failure-code taxonomy, `Connect`
  coalescing with `connect_in_progress`, and a self-enforced deadline even from
  cold readiness.
- Manifest v2 typed transports in place of hardcoded H3/H2 fields.
- Entry and exit on separate provider accounts, never co-hosted in privacy
  acceptance tests.
- Honest identification that the existing `DirectUDP` mobility enum is not an
  implementation.
- Patent language softened to candidate hypotheses for counsel rather than
  patentability conclusions.

## Open items the review raised that remain worth tracking

1. **iOS × Maximum Privacy is the riskiest intersection in the plan and
   surfaces late.** Tight extension memory, fixed-cell buffering, continuous
   cover traffic, and battery all land together, but the privacy data path is
   only ported in Phase 5 — after cross-platform Core in Phase 4. Consider a
   throwaway iOS feasibility spike on the privacy data path during Phase 4 so a
   blocking constraint appears while there is still room to redesign.

2. **The ~$350 initial cloud target may be optimistic** against a continuous
   seven-day soak from Phase 1 onward, entry/exit on separate provider accounts,
   and no co-hosting during privacy tests. Worth measuring actual burn early,
   given the project's donation-funded model.

Both are noted in this record only; the authoritative plan governs whether and
how they are acted on.
