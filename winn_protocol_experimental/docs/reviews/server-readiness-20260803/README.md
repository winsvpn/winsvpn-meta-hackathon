# Server-readiness review — 2026-08-03

**NON-AUTHORITATIVE.** Independent server-side review feeding an external audit.

| | |
|---|---|
| Contents | [`SERVER_READINESS_REVIEW.md`](SERVER_READINESS_REVIEW.md) |
| Scope | The three internet-facing server processes: `winn-server` (control plane), `winn-carrier-server` (data plane), `winn-token-issuer` |
| Verdict | **Not production ready.** Cryptography, audit design, and runbook are strong; probe resistance, revocation reach, pre-auth rate limiting, and database identifier handling are not. |

## Ranked gaps

| ID | Severity | Gap | Basis |
|---|---|---|---|
| P0-1 | Blocker | Probe resistance absent — five single-probe discriminators confirm the endpoint | Tested |
| P0-2 | Blocker | Device revocation never reaches the carrier data plane | Read |
| P0-3 | Blocker | PostgreSQL stores plaintext `device_id`; no retention on `winn_peers` | Read |
| P1-4 | High | Operational log leaked every peer IP — **FIXED, verified** | Tested → fixed → re-tested |
| P1-5 | High | Rate limiter runs only after authentication; no pre-auth connection limits | Tested |
| P1-6 | High | Gateway manifest expiry checked only at startup | Read |
| P1-7 | High | Identity-mode replay cache is per-process and in-memory | Read |
| P2-8 | Medium | `securefile` has no UID/ownership check on Unix | Read |
| P2-9 | Medium | No container image, no CI, no IaC; flags-only configuration | Read |
| P2-10 | Low | Committed build artifacts; `.gitignore` lacks key-file patterns | Read |

## Fix landed in this review

Peer-address redaction for operational logs (P1-4). Measured before: 3000
unauthenticated connections produced 3000 log lines carrying raw client
`IP:port`. Measured after: zero peer addresses, error classes preserved, no
functional regression.

```
internal/observability/errorlog.go        (new)
internal/observability/errorlog_test.go   (new)
cmd/winn-server/main.go                   (modified)
cmd/winn-carrier-server/main.go           (modified)
cmd/winn-token-issuer/main.go             (modified)
```

Nothing under `internal/carrier`, `docs/handoff/`, `evidence/`, or any
append-only log was modified. No key material appears in any file produced by
this review — locations only.

## Reproducing the probe results

A live `winn-carrier-server` was stood up in lab mode following
`scripts/carrier_smoke.sh`, then probed with OpenSSL 3.6.3 and a standalone Go
harness that imports nothing from the module under test. Section 0 of the review
lists all 18 tests and states, per finding, whether it was **exercised** or
**read**. Section 6 states the limits — notably that the controller, the issuer,
anonymous-token mode, Postgres, and Linux were **not** exercised.
