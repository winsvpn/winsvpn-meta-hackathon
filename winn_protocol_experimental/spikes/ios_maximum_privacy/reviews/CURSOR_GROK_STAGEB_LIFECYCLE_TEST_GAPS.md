# Stage B Provider Lifecycle — Test-Gap Audit

**Label: NON-AUTHORITATIVE.** Bounded defensive audit only. Claims must be independently re-verified by Codex before any production or test change. This lane did not modify production code or existing tests.

| Field | Value |
| --- | --- |
| Auditor | Cursor Grok (bounded non-authoritative lane) |
| Date (local) | 2026-07-27 |
| Scope root | `spikes/ios_maximum_privacy` |
| Source (only) | `PrivacyCore/Sources/WinnStageBProviderCore/StageBProviderLifecycle.swift` |
| Tests (only) | `PrivacyCore/Tests/WinnStageBProviderCoreTests/StageBProviderLifecycleTests.swift` |
| Source SHA-256 | `9afac27105b842bb35c4eab23011efc09fc1f039d40305bfeca02070001935c5` |
| Tests SHA-256 | `b5239eea7993022c604fa7824787b718216a06a953f4db93ded5f5ceec147065` |

---

## Commands and exits

Isolated SPM runs only. No shared verify/build/device/cloud scripts. Fresh `--build-path` under `.runtime/cursor-grok-lifecycle-testgaps/`.

### Attempt 1 (build.db I/O fault; XCTest green; process exit 1)

```bash
cd PrivacyCore
swift test --filter StageBProviderLifecycleTests \
  --build-path ../.runtime/cursor-grok-lifecycle-testgaps/swift-build
```

| Item | Result |
| --- | --- |
| Start (UTC) | `2026-07-27T07:46:28Z` |
| Build note | `error: accessing build database ".../swift-build/build.db": disk I/O error` then `Build complete!` |
| XCTest | `StageBProviderLifecycleTests` — **27 tests, 0 failures** |
| Process exit | **1** (attributed to build-db I/O error after a green XCTest run; not a test assertion failure) |

### Attempt 2 (authoritative for this audit’s pass/fail)

```bash
cd PrivacyCore
swift test --filter StageBProviderLifecycleTests \
  --build-path ../.runtime/cursor-grok-lifecycle-testgaps/swift-build-r2
```

| Item | Result |
| --- | --- |
| Start (UTC) | `2026-07-27T07:47:01Z` |
| End (UTC) | `2026-07-27T07:47:25Z` |
| Build | `Build complete!` (no build.db error) |
| XCTest | **Executed 27 tests, with 0 failures** |
| Process exit | **0** |

Note: SPM still compiles sibling targets in the package; only the lifecycle XCTest filter executed. A trailing Swift Testing banner reported `0 tests in 0 suites` and is unrelated to the XCTest suite above.

---

## Verdict (one line)

Existing coverage is strong on deadline freeze, first-terminal-wins, generation binding, orphan late-success after non-success terminals, and exact-once cleanup — but several high-impact success/orphan/clock/sequence edges emphasized for this audit are **untested**, including one path that can emit `stopEngineHandle` against a handle success intentionally kept.

---

## Prioritized findings

### P0 — missing tests that pin dangerous live-handle stop asymmetry

#### P0-1. Duplicate `recordStartSucceeded` after a **successful** terminal stops the kept handle

**Source behavior**

- Success path (`terminalEffectsLocked`, `reason == .succeeded`) keeps `current.handle` and sets `cleanupState = .notRequired` (never `cleaned`).
- While `.running`, same-handle duplicate → `.ignoredDuplicate`, **no** stop (`recordStartSucceeded` `.running` branch).
- After `.terminal` / `.cleaned`, any `recordStartSucceeded` — including the **same** generation and **same** handle — takes the orphan path:

```385:390:PrivacyCore/Sources/WinnStageBProviderCore/StageBProviderLifecycle.swift
    case .idle, .terminal, .cleaned:
      return orphanDirectiveLocked(
        .ignoredTerminal,
        generation: generation,
        handle: handle
      )
```

`orphanDirectiveLocked` always increments `staleStops` and emits `.stopEngineHandle(handle)`.

**Existing tests**

- `testDuplicateStartSuccessWithTheSameHandleIsIdempotent` — only while `.running`.
- `testLateStartSuccessAfterTerminalStopsTheOrphanedHandle` — late success after **`.cancelled`** (no prior adopted handle).
- `testSuccessKeepsTheHandleAndRequiresNoCleanup` — does **not** re-deliver start-success after success.

**Concrete missing test**

1. `beginAttempt` → `recordStartSucceeded(H)` → `recordTerminal(.succeeded)`.
2. Re-call `recordStartSucceeded` with the **same** generation and **same** `H`.
3. Assert the intended contract explicitly:
   - Either: disposition ignores **without** stop / without bumping `staleEngineHandleStopsDirected` / snapshot still owns `H` (symmetric with running duplicate), **or**
   - If stop-on-terminal-duplicate is intentional: document that callers must never re-enter start-success after success, and assert snapshot/`staleEngineHandleStopsDirected`/effects accordingly.
4. Today’s code emits stop while `engineHandleOwned` remains `true` — that split is untested and is the P0 hazard if callers obey effects.

#### P0-2. `recordTerminal(.succeeded)` while still `.starting` (no engine handle)

**Source behavior**

`recordTerminal` accepts `.succeeded` from `.starting` when the clock verdict has no override. `terminalEffectsLocked` then sets `cleanupState = .notRequired` without requiring a handle. Snapshot: `state == .terminal`, `terminalReason == .succeeded`, `engineHandleOwned == false`. Because success never reaches `.cleaned`, `beginAttempt` afterward throws `.invalidState` — the machine is stuck in a “succeeded with no tunnel” terminal.

**Existing tests**

- `testSuccessKeepsTheHandleAndRequiresNoCleanup` always adopts a handle first.
- `testStartFailedBeforeAnyHandleIsAcceptedAndCleansUp` covers failure-without-handle, not success-without-handle.
- Post-deadline override of requested `.succeeded` is covered; on-time success-without-handle is not.

**Concrete missing test**

1. From `.starting` with no handle, `recordTerminal(reason: .succeeded, now: on-time)`.
2. Assert either rejection / fail-closed cleanup **or** (if allowed) pin: `succeeded` + `notRequired` + `!engineHandleOwned` + subsequent `beginAttempt` → `.invalidState`.
3. Mirror with on-time `.succeeded` one nanosecond before deadline vs after deadline (deadline override already partially covered).

---

### P1 — missing tests on emphasized edges

#### P1-1. Stale-generation start-success whose raw handle value aliases the live generation’s handle

**Source behavior**

Stale `recordStartSucceeded` always returns `orphanDirectiveLocked(.ignoredStaleGeneration, …)` with `.stopEngineHandle` bound to the **stale** generation, without inspecting whether the live attempt currently owns the same `Int32`.

**Existing tests**

- `testStaleGenerationInputsAreObservableNoOps` uses orphan handle `11` while generation 2 is still `.starting` and owns **no** handle.
- Does not cover: gen2 `.running` with handle `H`, then stale gen1 `recordStartSucceeded` with the same raw `H`.

**Concrete missing test**

1. Complete gen1 → cleanup → `beginAttempt` gen2 → `recordStartSucceeded(H)` on gen2.
2. Deliver stale gen1 `recordStartSucceeded(H)` (same `value`).
3. Assert: live snapshot still owns `H` / state `.running`; effect is generation-bound to gen1; `staleEngineHandleStopsDirected` increments; document that callers must gate stops by effect.generation, not raw handle alone.

#### P1-2. Caller-fabricated internal-only clock/deadline reasons

**Source behavior**

`recordTerminal` uses `verdict.override ?? reason`. When the clock is trusted and on-time, a caller may pass `.deadlineExceeded`, `.clockRollback`, or `.clockOutOfRange` and have them recorded as the authoritative terminal reason with `.accepted`.

**Existing tests**

- `testTerminalAfterDeadlineIsRecordedAsDeadlineExceeded` requests ordinary reasons after deadline (override wins).
- No test requests the clock/deadline enum cases **before** deadline / with a trusted clock.

**Concrete missing test**

For each of `.deadlineExceeded`, `.clockRollback`, `.clockOutOfRange` while `now` is in `[watermark, deadline]`:

1. Call `recordTerminal(reason: fabricated, …)`.
2. Pin whether the machine should accept-as-labeled, reject, or remap — today’s code accepts-as-labeled; that contract is untested.

#### P1-3. Cleanup completion vs rollback / out-of-range instants

**Source behavior**

`recordCleanupCompleted` does **not** call `clockVerdictLocked`. It transitions to `.cleaned` first, then classifies budget with `now >= terminalAt && now <= cleanupDeadline`. Failures become `.completedOverBudget` + `.rejected` and do **not** advance `monotonicWatermark`. There is no `.clockRollback` / `.clockOutOfRange` outcome on this path.

**Existing tests**

- Exact budget boundary accepted (`testCleanupIsAcceptedOnceAtTheExactBudgetBoundary`).
- `now == terminalAt - 1` and `cleanupDeadline + 1` → over-budget (`testCleanupOneNanosecondPastTheBudgetIsOverBudget`).
- Missing: assert cleanup **never** reports clock reasons; missing extreme `now` (e.g. `0`, `UInt64.max`) while terminal pending; missing that over-budget cleanup still leaves `.cleaned` so a later `beginAttempt` can proceed (retry-after-over-budget).

**Concrete missing tests**

1. After non-success terminal, `recordCleanupCompleted(now: 0)` and `now: UInt64.max` → `.rejected` / `.completedOverBudget` / `.cleaned`; watermark unchanged on reject.
2. Explicit XCTAssert that `terminalReason` remains the original non-clock reason (no remap to `.clockRollback` / `.clockOutOfRange`).
3. `beginAttempt` after over-budget cleanup succeeds with a fresh nonce/T0 (proves over-budget does not wedge the machine).

#### P1-4. `nextSequence` overflow / wrap to zero

**Source behavior**

`beginAttempt` assigns `sequence: nextSequence` then does unchecked `nextSequence += 1`. After a successful mint with `sequence == UInt64.max`, `nextSequence` wraps to `0`. The next `beginAttempt` (after cleanup) calls `StageBLifecycleGeneration(..., sequence: 0)` which throws `.invalidGeneration` **after** preconditions pass but **before** replacing `attempt` — permanently wedging further starts on that instance.

**Existing tests**

- Sequence `0` rejected at type init (`testGenerationAndHandleValidationRejectMalformedInputs`).
- Second attempt gets `sequence: 2` after one cleaned generation (`testBeginRejectsReusedNonceReusedT0AndUncleanedState`).
- No overflow / saturating / wedge test.

**Concrete missing test**

1. Drive or inject the machine to the post-`UInt64.max` sequence state (test-only seam, mirror type, or bounded internal hook — out of scope for this lane to add).
2. Assert either: begin refuses with a dedicated error **before** wrap, or wrap is impossible via saturating `nextSequence`, or document permanent wedge after `UInt64.max` generations.
3. Until then, treat overflow as an untested availability edge.

#### P1-5. Concurrency beyond concurrent terminals

**Existing tests**

- `testConcurrentTerminalsProduceOneOutcomeAndOneCleanup` — 64× `recordTerminal` only.

**Concrete missing tests**

1. `concurrentPerform`: `recordStartSucceeded` racing `recordTerminal(.cancelled)` from `.starting` — exactly one of adopt-then-cancel vs cancel-then-orphan-stop; never adopted handle without a matching stop on the losing path.
2. `recordStartSucceeded` racing `recordStartFailed`.
3. Two `recordCleanupCompleted` calls concurrent after one terminal — one `.accepted`/`.rejected` budget winner semantics, one `.ignoredDuplicate`, state ends `.cleaned` once.
4. `recordStartSucceeded(same H)` racing another `recordStartSucceeded(same H)` while `.running` — only `.accepted` + `.ignoredDuplicate` (no stop).

Reentrancy note: methods release the lock before returning; effect execution by the caller is outside the lock. Missing a documented “caller may re-enter after receiving a directive” smoke (e.g. on `.accepted` terminal, synchronously `recordCleanupCompleted` then `beginAttempt`). Not a machine deadlock bug by inspection; still an untested integration assumption → keep at P1 for the race matrix, P2 for simple post-return reentry.

---

### P2 — lower-priority gaps

| ID | Gap | Notes |
| --- | --- | --- |
| P2-1 | `recordStartSucceeded` / `recordStartFailed` with `now < watermark` (clock rollback) | Timer rollback covered; start-success/fail rollback not. |
| P2-2 | Start-success with `now > admissibleCeiling` | Deadline+1 covered; ceiling+1 on start-success not. |
| P2-3 | After `.succeeded`, `beginAttempt` → `.invalidState` | Implied by design comments; not asserted. |
| P2-4 | Snapshot schema / `cleanupDirectivesEmitted` lifetime reset across generations | Second begin resets per-attempt counters; only lightly touched. |
| P2-5 | `recordTerminal` from `.running` with every allowlisted non-success reason | Partial coverage via concurrent winner set / one networkSettings path. |
| P2-6 | Negative-handle construction only tests `-1` | Zero accepted; other negatives omitted (low value). |

---

## Concrete missing-test checklist (copy-ready)

1. **Success-before-handle:** `recordTerminal(.succeeded)` in `.starting` with `handle == nil`.
2. **Duplicate success-after-success-terminal:** same generation + same handle after `.succeeded`; assert stop vs ignore contract.
3. **Stale success handle alias:** live gen owns `H`; stale gen delivers `recordStartSucceeded(H)`.
4. **Fabricated clock reasons on-time:** `.deadlineExceeded` / `.clockRollback` / `.clockOutOfRange` via `recordTerminal` before deadline.
5. **Cleanup extreme/rollback-shaped times:** `now = 0`, `UInt64.max`; assert no clock-reason remap; watermark policy; retry `beginAttempt` after over-budget.
6. **`nextSequence` at `UInt64.max`:** wrap/wedge/saturate contract.
7. **Concurrency matrix:** start-success×terminal, start-success×start-failed, dual cleanup, dual same-handle success.
8. **Post-success beginAttempt invalidState** (P2) and start-path clock rollback/ceiling (P2).

---

## False positives rejected

| Claim | Why rejected |
| --- | --- |
| “First terminal can be overwritten” | Contradicted by `testFirstTerminalWinsAndLaterTerminalsCannotOverwriteIt` and concurrent single-acceptor test. |
| “Cleanup directive can emit twice for one generation” | Contradicted by `testCleanupDirectiveIsEmittedExactlyOncePerGeneration`. |
| “Deadline is recomputed from processing time” | Contradicted by `testDeadlineIsFrozenAtT0AndNotAtProcessingTime` / exact rearm tests. |
| “Duplicate same-handle success while `.running` stops the live handle” | Contradicted by `testDuplicateStartSuccessWithTheSameHandleIsIdempotent` (`.ignoredDuplicate`, empty effects). |
| “Stale inputs move the live watermark” | Contradicted by `testStaleInputCannotMoveTheLiveClockWatermark`. |
| “Late success after non-success terminal leaks without stop” | Contradicted by late-success-after-terminal/cleanup tests (orphan stop). |
| “Inclusive deadline incorrectly terminals” | Contradicted by rearm-at-deadline and inclusive-deadline reason retention tests. |
| “Attempt object in `.idle` is a reachable production state needing tests” | Comments state attempts never carry `.idle`; branch is defensive. Not filed as a gap. |
| “Attempt-1 process exit 1 means lifecycle tests failed” | XCTest reported 0 failures; exit 1 coincided with build.db I/O error. Attempt 2 exit 0 confirms green. |

---

## Coverage map (emphasized themes)

| Theme | Covered today? | Residual |
| --- | --- | --- |
| Success before engine handle exists | No | P0-2 |
| Duplicate start-success after successful terminal | No (only while running / after cancel) | P0-1 |
| Stale callback, handle value aliases live handle | Partial (stale without live handle) | P1-1 |
| Caller-fabricated deadline/clock reasons | No | P1-2 |
| Cleanup + rollback/out-of-range-shaped time | Partial (early/late as over-budget only) | P1-3 |
| `nextSequence` overflow | No | P1-4 |
| Concurrency / reentrancy | Partial (terminals only) | P1-5 |

---

## Out of scope / method limits

- Read only the two named Swift files; no coordinator, codec, scripts, credentials, git history, progress logs, engine binaries, framework loader, or crypto primitives.
- No production or test edits; no shared verify/device/cloud.
- Did not execute a crafted overflow harness (would require test changes or internals).
- **NON-AUTHORITATIVE:** Codex must re-hash both files, re-run the filtered test, and re-derive each P0/P1 claim from source before acting.

---

*End of report.*
