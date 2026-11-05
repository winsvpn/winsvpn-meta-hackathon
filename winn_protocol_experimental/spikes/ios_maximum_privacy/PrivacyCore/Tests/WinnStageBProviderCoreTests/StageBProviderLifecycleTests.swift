import Foundation
import WinnPrivacyCore
import WinnStageBProviderCore
import XCTest

/// Frozen contract values restated as literals.
///
/// The expectations below never read the production constants, so a mutation
/// of either constant changes only one side of every comparison.
private let successBudget: UInt64 = 3_000_000_000
private let cleanupBudget: UInt64 = 250_000_000

final class StageBProviderLifecycleTests: XCTestCase {
  private let t0: UInt64 = 1_000_000
  private var deadline: UInt64 { t0 + successBudget }

  func testFrozenBudgetsMatchTheContractLiterals() {
    XCTAssertEqual(
      StageBProviderLifecycle.cleanupBudgetNanoseconds,
      cleanupBudget
    )
    XCTAssertEqual(
      StageBProtectedFlow.deadlineNanoseconds,
      successBudget
    )
    XCTAssertEqual(
      StageBLifecycleCancellationScope.allCases.count,
      3
    )
  }

  func testGenerationAndHandleValidationRejectMalformedInputs() throws {
    var notVersionFour = lifecycleUUID(0x21)
    notVersionFour[6] = 0x50
    XCTAssertThrowsError(
      try StageBLifecycleGeneration(
        attemptNonce: notVersionFour,
        sequence: 1
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidIdentifier
      )
    }
    var notRFCVariant = lifecycleUUID(0x21)
    notRFCVariant[8] = 0x0f
    XCTAssertThrowsError(
      try StageBLifecycleGeneration(
        attemptNonce: notRFCVariant,
        sequence: 1
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidIdentifier
      )
    }
    XCTAssertThrowsError(
      try StageBLifecycleGeneration(
        attemptNonce: Array(lifecycleUUID(0x21).dropLast()),
        sequence: 1
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidIdentifier
      )
    }
    XCTAssertThrowsError(
      try StageBLifecycleGeneration(
        attemptNonce: lifecycleUUID(0x21),
        sequence: 0
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidGeneration
      )
    }
    XCTAssertThrowsError(try StageBLifecycleEngineHandle(-1)) {
      XCTAssertEqual($0 as? StageBLifecycleError, .invalidHandle)
    }
    XCTAssertEqual(try StageBLifecycleEngineHandle(0).value, 0)
  }

  // MARK: absolute T0 deadline

  func testDeadlineIsFrozenAtT0AndNotAtProcessingTime() throws {
    let machine = StageBProviderLifecycle()
    let generation = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x21),
      sequence: 1
    )
    // startTunnel is entered with only one nanosecond of budget left.
    let lateStart = t0 + successBudget - 1
    let directive = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: lateStart
    )
    XCTAssertEqual(
      directive,
      StageBLifecycleDirective(
        disposition: .accepted,
        state: .starting,
        terminalReason: nil,
        effects: [
          StageBLifecycleEffect(
            generation: generation,
            action: .armDeadlineTimer(
              atMonotonicNanoseconds: t0 + successBudget + 1
            )
          )
        ]
      )
    )
    let snapshot = machine.snapshot()
    XCTAssertEqual(snapshot.t0MonotonicNanoseconds, t0)
    XCTAssertEqual(
      snapshot.deadlineMonotonicNanoseconds,
      t0 + successBudget
    )
    XCTAssertEqual(snapshot.generation, generation)

    // The remaining budget is one nanosecond measured from T0, not a fresh
    // three seconds measured from the late entry.
    XCTAssertEqual(
      machine.handleDeadlineTimerFired(
        generation: generation,
        atMonotonicNanoseconds: t0 + successBudget
      ).disposition,
      .accepted
    )
    XCTAssertEqual(machine.snapshot().state, .starting)
    let expired = machine.handleDeadlineTimerFired(
      generation: generation,
      atMonotonicNanoseconds: t0 + successBudget + 1
    )
    XCTAssertEqual(expired.disposition, .accepted)
    XCTAssertEqual(expired.terminalReason, .deadlineExceeded)
    XCTAssertEqual(
      machine.snapshot().terminalAtMonotonicNanoseconds,
      t0 + successBudget + 1
    )
  }

  func testTimerAtExactDeadlineRearmsAtDeadlinePlusOne() throws {
    let (machine, generation) = try started()
    let rearm = machine.handleDeadlineTimerFired(
      generation: generation,
      atMonotonicNanoseconds: deadline
    )
    XCTAssertEqual(
      rearm,
      StageBLifecycleDirective(
        disposition: .accepted,
        state: .starting,
        terminalReason: nil,
        effects: [
          StageBLifecycleEffect(
            generation: generation,
            action: .armDeadlineTimer(
              atMonotonicNanoseconds: deadline + 1
            )
          )
        ]
      )
    )
    XCTAssertNil(machine.snapshot().terminalReason)

    let terminal = machine.handleDeadlineTimerFired(
      generation: generation,
      atMonotonicNanoseconds: deadline + 1
    )
    XCTAssertEqual(terminal.disposition, .accepted)
    XCTAssertEqual(
      terminal.effects,
      cancelEffects(generation) + [
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: deadline + 1 + cleanupBudget
          )
        )
      ]
    )
    XCTAssertEqual(machine.snapshot().state, .terminal)
    XCTAssertEqual(
      machine.snapshot().terminalReason,
      .deadlineExceeded
    )
  }

  func testTerminalAfterDeadlineIsRecordedAsDeadlineExceeded() throws {
    let requested: [StageBLifecycleRequestedTerminalReason] = [
      .succeeded, .stopped, .cancelled, .superseded, .pathChanged,
    ]
    for reason in requested {
      // A running attempt that owns its handle, so `succeeded` is admissible
      // and only the deadline decides the outcome.
      let onTime = try startedRunning()
      let accepted = onTime.0.recordTerminal(
        generation: onTime.1,
        reason: reason,
        atMonotonicNanoseconds: deadline
      )
      XCTAssertEqual(accepted.disposition, .accepted)
      XCTAssertEqual(
        onTime.0.snapshot().terminalReason,
        reason.recorded,
        "at the inclusive deadline the requested reason stands"
      )

      let late = try startedRunning()
      let rejected = late.0.recordTerminal(
        generation: late.1,
        reason: reason,
        atMonotonicNanoseconds: deadline + 1
      )
      XCTAssertEqual(rejected.disposition, .rejected)
      XCTAssertEqual(
        late.0.snapshot().terminalReason,
        .deadlineExceeded,
        "one nanosecond past the deadline outranks \(reason)"
      )
    }
  }

  func testBeginRejectsOverflowingT0AndPostDeadlineEntry() throws {
    // The largest T0 whose deadline, admissible ceiling and cleanup headroom
    // are all representable.
    let widest = UInt64.max - successBudget - 3 * cleanupBudget
    let widestMachine = StageBProviderLifecycle()
    XCTAssertNoThrow(
      try widestMachine.beginAttempt(
        attemptNonce: lifecycleUUID(0x21),
        t0MonotonicNanoseconds: widest,
        atMonotonicNanoseconds: widest
      )
    )
    for overflowing in [widest + 1, UInt64.max - successBudget, UInt64.max] {
      let machine = StageBProviderLifecycle()
      XCTAssertThrowsError(
        try machine.beginAttempt(
          attemptNonce: lifecycleUUID(0x21),
          t0MonotonicNanoseconds: overflowing,
          atMonotonicNanoseconds: overflowing
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBLifecycleError,
          .invalidDeadline,
          "T0 \(overflowing) must not be accepted"
        )
      }
      XCTAssertEqual(machine.snapshot().state, .idle)
    }

    let backwards = StageBProviderLifecycle()
    XCTAssertThrowsError(
      try backwards.beginAttempt(
        attemptNonce: lifecycleUUID(0x21),
        t0MonotonicNanoseconds: t0,
        atMonotonicNanoseconds: t0 - 1
      )
    ) {
      XCTAssertEqual($0 as? StageBLifecycleError, .invalidDeadline)
    }

    let expired = StageBProviderLifecycle()
    XCTAssertThrowsError(
      try expired.beginAttempt(
        attemptNonce: lifecycleUUID(0x21),
        t0MonotonicNanoseconds: t0,
        atMonotonicNanoseconds: deadline + 1
      )
    ) {
      XCTAssertEqual($0 as? StageBLifecycleError, .invalidDeadline)
    }
    XCTAssertEqual(expired.snapshot().state, .idle)

    let atDeadline = StageBProviderLifecycle()
    XCTAssertNoThrow(
      try atDeadline.beginAttempt(
        attemptNonce: lifecycleUUID(0x21),
        t0MonotonicNanoseconds: t0,
        atMonotonicNanoseconds: deadline
      )
    )
  }

  // MARK: generation binding

  func testBeginRejectsReusedNonceReusedT0AndUncleanedState() throws {
    let (machine, generation) = try started()
    XCTAssertThrowsError(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: t0 + 1,
        atMonotonicNanoseconds: t0 + 1
      )
    ) {
      XCTAssertEqual($0 as? StageBLifecycleError, .invalidState)
    }

    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 10
    )
    XCTAssertThrowsError(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: t0 + 1,
        atMonotonicNanoseconds: t0 + 20
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidState,
        "a terminal attempt awaiting cleanup cannot be replaced"
      )
    }
    _ = machine.recordCleanupCompleted(
      generation: generation,
      atMonotonicNanoseconds: t0 + 20
    )
    XCTAssertEqual(machine.snapshot().state, .cleaned)

    XCTAssertThrowsError(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x21),
        t0MonotonicNanoseconds: t0 + 1,
        atMonotonicNanoseconds: t0 + 20
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidIdentifier,
        "the attempt nonce cannot be replayed"
      )
    }
    XCTAssertThrowsError(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: t0,
        atMonotonicNanoseconds: t0 + 20
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidDeadline,
        "T0 cannot be reset to the previous first click"
      )
    }

    let retry = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x31),
      t0MonotonicNanoseconds: t0 + 1_000_000_000,
      atMonotonicNanoseconds: t0 + 1_000_000_000
    )
    let second = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: 2
    )
    XCTAssertEqual(
      retry,
      StageBLifecycleDirective(
        disposition: .accepted,
        state: .starting,
        terminalReason: nil,
        effects: [
          StageBLifecycleEffect(
            generation: second,
            action: .armDeadlineTimer(
              atMonotonicNanoseconds:
                t0 + 1_000_000_000 + successBudget + 1
            )
          )
        ]
      )
    )
    XCTAssertEqual(
      machine.snapshot().deadlineMonotonicNanoseconds,
      t0 + 1_000_000_000 + successBudget
    )
    XCTAssertEqual(machine.snapshot().cleanupDirectivesEmitted, 0)
  }

  func testGenerationIdentityRequiresBothNonceAndSequence() throws {
    let (machine, generation) = try started()
    let sameNonceLaterSequence = try StageBLifecycleGeneration(
      attemptNonce: generation.attemptNonce,
      sequence: generation.sequence + 1
    )
    let otherNonceSameSequence = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: generation.sequence
    )
    XCTAssertNotEqual(sameNonceLaterSequence, generation)
    XCTAssertNotEqual(otherNonceSameSequence, generation)

    for impostor in [sameNonceLaterSequence, otherNonceSameSequence] {
      XCTAssertEqual(
        machine.recordTerminal(
          generation: impostor,
          reason: .cancelled,
          atMonotonicNanoseconds: t0 + 10
        ),
        StageBLifecycleDirective(
          disposition: .ignoredStaleGeneration,
          state: .starting,
          terminalReason: nil,
          effects: []
        )
      )
      XCTAssertNil(machine.snapshot().terminalReason)
    }

    // The real generation still works, so the rejections above were not a
    // blanket refusal.
    XCTAssertEqual(
      machine.recordTerminal(
        generation: generation,
        reason: .cancelled,
        atMonotonicNanoseconds: t0 + 10
      ).disposition,
      .accepted
    )
    XCTAssertEqual(machine.snapshot().terminalReason, .cancelled)
  }

  func testStaleGenerationInputsAreObservableNoOps() throws {
    let machine = StageBProviderLifecycle()
    let first = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x21),
      sequence: 1
    )
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    _ = machine.recordTerminal(
      generation: first,
      reason: .superseded,
      atMonotonicNanoseconds: t0 + 10
    )
    _ = machine.recordCleanupCompleted(
      generation: first,
      atMonotonicNanoseconds: t0 + 20
    )
    let secondT0 = t0 + 1_000_000_000
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x31),
      t0MonotonicNanoseconds: secondT0,
      atMonotonicNanoseconds: secondT0
    )
    let second = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: 2
    )
    XCTAssertEqual(machine.snapshot().generation, second)

    let before = machine.snapshot()
    let expectedStale = StageBLifecycleDirective(
      disposition: .ignoredStaleGeneration,
      state: .starting,
      terminalReason: nil,
      effects: []
    )
    XCTAssertEqual(
      machine.recordStartFailed(
        generation: first,
        atMonotonicNanoseconds: secondT0 + 5
      ),
      expectedStale
    )
    XCTAssertEqual(
      machine.recordTerminal(
        generation: first,
        reason: .stopped,
        atMonotonicNanoseconds: secondT0 + 5
      ),
      expectedStale
    )
    XCTAssertEqual(
      machine.handleDeadlineTimerFired(
        generation: first,
        atMonotonicNanoseconds: secondT0 + successBudget + 1
      ),
      expectedStale
    )
    XCTAssertEqual(
      machine.recordCleanupCompleted(
        generation: first,
        atMonotonicNanoseconds: secondT0 + 5
      ),
      expectedStale
    )
    XCTAssertEqual(
      machine.snapshot(),
      before,
      "no stale input changed one recorded field"
    )

    // The one stale input that must still produce work: a turn-on that
    // completed for the abandoned generation.
    let orphan = try StageBLifecycleEngineHandle(11)
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: first,
        handle: orphan,
        atMonotonicNanoseconds: secondT0 + 5
      ),
      StageBLifecycleDirective(
        disposition: .ignoredStaleGeneration,
        state: .starting,
        terminalReason: nil,
        effects: [
          StageBLifecycleEffect(
            generation: first,
            action: .stopEngineHandle(orphan)
          )
        ]
      )
    )
    let after = machine.snapshot()
    XCTAssertEqual(after.generation, second)
    XCTAssertEqual(after.state, .starting)
    XCTAssertFalse(
      after.engineHandleOwned,
      "the orphaned handle must never be adopted by the live generation"
    )
    XCTAssertNil(after.terminalReason)
    XCTAssertEqual(after.cleanupDirectivesEmitted, 0)
    XCTAssertEqual(after.staleEngineHandleStopsDirected, 1)
    XCTAssertEqual(before.staleEngineHandleStopsDirected, 0)
  }

  func testStaleInputCannotMoveTheLiveClockWatermark() throws {
    let (machine, generation) = try started()
    let stale = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: 1
    )
    // A stale callback carrying an instant far in the future.
    XCTAssertEqual(
      machine.recordTerminal(
        generation: stale,
        reason: .stopped,
        atMonotonicNanoseconds: deadline
      ).disposition,
      .ignoredStaleGeneration
    )
    XCTAssertEqual(
      machine.handleDeadlineTimerFired(
        generation: stale,
        atMonotonicNanoseconds: deadline + 1
      ).disposition,
      .ignoredStaleGeneration
    )

    // The live generation's own callback, sampled long before those stale
    // instants, is still on time.
    let handle = try StageBLifecycleEngineHandle(7)
    let accepted = machine.recordStartSucceeded(
      generation: generation,
      handle: handle,
      atMonotonicNanoseconds: t0 + 1_000
    )
    XCTAssertEqual(
      accepted,
      StageBLifecycleDirective(
        disposition: .accepted,
        state: .running,
        terminalReason: nil,
        effects: []
      )
    )
    XCTAssertTrue(machine.snapshot().engineHandleOwned)
  }

  // MARK: first terminal wins

  func testFirstTerminalWinsAndLaterTerminalsCannotOverwriteIt() throws {
    let (machine, generation) = try started()
    let handle = try StageBLifecycleEngineHandle(4)
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: handle,
      atMonotonicNanoseconds: t0 + 100
    )
    let terminal = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 1_000
    )
    XCTAssertEqual(terminal.disposition, .accepted)
    XCTAssertEqual(
      terminal.effects,
      cancelEffects(generation) + [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(handle)
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 1_000 + cleanupBudget
          )
        ),
      ]
    )
    let recorded = machine.snapshot()
    XCTAssertEqual(recorded.terminalReason, .cancelled)
    XCTAssertEqual(
      recorded.terminalAtMonotonicNanoseconds,
      t0 + 1_000
    )
    XCTAssertEqual(
      recorded.cleanupDeadlineMonotonicNanoseconds,
      t0 + 1_000 + cleanupBudget
    )
    XCTAssertEqual(recorded.cleanupDirectivesEmitted, 1)

    let expectedIgnored = StageBLifecycleDirective(
      disposition: .ignoredTerminal,
      state: .terminal,
      terminalReason: .cancelled,
      effects: []
    )
    for reason in [
      StageBLifecycleRequestedTerminalReason.succeeded,
      .superseded,
      .stopped,
      .bindingMismatch,
    ] {
      XCTAssertEqual(
        machine.recordTerminal(
          generation: generation,
          reason: reason,
          atMonotonicNanoseconds: t0 + 2_000
        ),
        expectedIgnored
      )
    }
    XCTAssertEqual(
      machine.recordStartFailed(
        generation: generation,
        atMonotonicNanoseconds: t0 + 2_000
      ),
      expectedIgnored
    )
    XCTAssertEqual(
      machine.handleDeadlineTimerFired(
        generation: generation,
        atMonotonicNanoseconds: deadline + 1
      ),
      expectedIgnored
    )
    XCTAssertEqual(
      machine.snapshot(),
      recorded,
      "no later terminal attempt changed the recorded outcome"
    )
  }

  func testConcurrentTerminalsProduceOneOutcomeAndOneCleanup() throws {
    let (machine, generation) = try started()
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: try StageBLifecycleEngineHandle(9),
      atMonotonicNanoseconds: t0 + 100
    )
    let reasons: [StageBLifecycleRequestedTerminalReason] = [
      .stopped, .cancelled, .superseded, .pathChanged,
      .engineChanged, .networkSettingsChanged, .bindingMismatch,
      .succeeded,
    ]
    let results = LockedDirectives()
    DispatchQueue.concurrentPerform(iterations: 64) { index in
      results.append(
        machine.recordTerminal(
          generation: generation,
          reason: reasons[index % reasons.count],
          atMonotonicNanoseconds: t0 + 1_000
        )
      )
    }
    let all = results.value
    XCTAssertEqual(all.count, 64)
    XCTAssertEqual(
      all.filter { $0.disposition == .accepted }.count,
      1
    )
    XCTAssertEqual(
      all.filter { $0.disposition == .ignoredTerminal }.count,
      63
    )
    let cleanupDirectives = all.flatMap(\.effects).filter {
      if case .runCleanup = $0.action { return true }
      return false
    }
    let recorded = machine.snapshot()
    let winner = try XCTUnwrap(recorded.terminalReason)
    XCTAssertTrue(reasons.map(\.recorded).contains(winner))
    // The winner may be `succeeded`, which requires no cleanup at all.
    XCTAssertEqual(cleanupDirectives.count, winner == .succeeded ? 0 : 1)
    XCTAssertEqual(
      recorded.cleanupDirectivesEmitted,
      cleanupDirectives.count
    )
    XCTAssertEqual(recorded.state, .terminal)
  }

  // MARK: cancellation directives

  func testNonSuccessTerminalCancelsEveryScopeExactlyOnce() throws {
    let (machine, generation) = try started()
    let handle = try StageBLifecycleEngineHandle(2)
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: handle,
      atMonotonicNanoseconds: t0 + 5
    )
    let directive = machine.recordTerminal(
      generation: generation,
      reason: .networkSettingsChanged,
      atMonotonicNanoseconds: t0 + 50
    )
    XCTAssertEqual(
      directive.effects,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .cancel(.timers)
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .cancel(.sockets)
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .cancel(.nativeWork)
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(handle)
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 50 + cleanupBudget
          )
        ),
      ]
    )
    var cancelled = [StageBLifecycleCancellationScope]()
    for effect in directive.effects {
      if case let .cancel(scope) = effect.action {
        cancelled.append(scope)
      }
      XCTAssertEqual(effect.generation, generation)
    }
    XCTAssertEqual(cancelled, [.timers, .sockets, .nativeWork])
    XCTAssertFalse(machine.snapshot().engineHandleOwned)
  }

  func testSuccessKeepsTheHandleAndRequiresNoCleanup() throws {
    let (machine, generation) = try started()
    let handle = try StageBLifecycleEngineHandle(3)
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: handle,
      atMonotonicNanoseconds: t0 + 5
    )
    let directive = machine.recordTerminal(
      generation: generation,
      reason: .succeeded,
      atMonotonicNanoseconds: deadline
    )
    XCTAssertEqual(directive.disposition, .accepted)
    XCTAssertEqual(
      directive.effects,
      cancelEffects(generation),
      "success cancels side work but never stops the engine"
    )
    let recorded = machine.snapshot()
    XCTAssertTrue(recorded.engineHandleOwned)
    XCTAssertEqual(recorded.cleanupState, .notRequired)
    XCTAssertEqual(recorded.cleanupDirectivesEmitted, 0)
    XCTAssertNil(recorded.cleanupDeadlineMonotonicNanoseconds)

    XCTAssertEqual(
      machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: deadline + 1
      ).disposition,
      .ignoredNotApplicable
    )
    XCTAssertEqual(
      machine.snapshot(),
      recorded,
      "a successful attempt is never cleaned"
    )
  }

  // MARK: late wgTurnOn success

  func testLateStartSuccessAfterTerminalStopsTheOrphanedHandle() throws {
    let (machine, generation) = try started()
    let cancelled = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 10
    )
    XCTAssertEqual(
      cancelled.effects,
      cancelEffects(generation) + [
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 10 + cleanupBudget
          )
        )
      ],
      "no handle exists yet, so nothing is stopped at the terminal"
    )

    // wgTurnOn now reports success for an attempt nobody is waiting on.
    let orphan = try StageBLifecycleEngineHandle(9)
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: generation,
        handle: orphan,
        atMonotonicNanoseconds: t0 + 20
      ),
      StageBLifecycleDirective(
        disposition: .ignoredTerminal,
        state: .terminal,
        terminalReason: .cancelled,
        effects: [
          StageBLifecycleEffect(
            generation: generation,
            action: .stopEngineHandle(orphan)
          )
        ]
      )
    )
    let recorded = machine.snapshot()
    XCTAssertFalse(recorded.engineHandleOwned)
    XCTAssertEqual(recorded.terminalReason, .cancelled)
    XCTAssertEqual(
      recorded.terminalAtMonotonicNanoseconds,
      t0 + 10
    )
    XCTAssertEqual(recorded.cleanupDirectivesEmitted, 1)
    XCTAssertEqual(recorded.staleEngineHandleStopsDirected, 1)
  }

  func testLateStartSuccessAfterCleanupStillStopsTheHandle() throws {
    let (machine, generation) = try started()
    _ = machine.recordTerminal(
      generation: generation,
      reason: .stopped,
      atMonotonicNanoseconds: t0 + 10
    )
    _ = machine.recordCleanupCompleted(
      generation: generation,
      atMonotonicNanoseconds: t0 + 20
    )
    XCTAssertEqual(machine.snapshot().state, .cleaned)

    let orphan = try StageBLifecycleEngineHandle(12)
    let directive = machine.recordStartSucceeded(
      generation: generation,
      handle: orphan,
      atMonotonicNanoseconds: t0 + 30
    )
    XCTAssertEqual(directive.disposition, .ignoredTerminal)
    XCTAssertEqual(
      directive.effects,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(orphan)
        )
      ]
    )
    XCTAssertEqual(machine.snapshot().state, .cleaned)
    XCTAssertFalse(machine.snapshot().engineHandleOwned)
  }

  func testStartSuccessPastTheDeadlineIsRejectedAndStopsTheHandle()
    throws
  {
    let onTime = try started()
    let liveHandle = try StageBLifecycleEngineHandle(5)
    XCTAssertEqual(
      onTime.0.recordStartSucceeded(
        generation: onTime.1,
        handle: liveHandle,
        atMonotonicNanoseconds: deadline
      ).disposition,
      .accepted,
      "turn-on landing exactly at the deadline is adopted"
    )
    XCTAssertEqual(onTime.0.snapshot().state, .running)
    XCTAssertTrue(onTime.0.snapshot().engineHandleOwned)

    let late = try started()
    let lateHandle = try StageBLifecycleEngineHandle(6)
    let directive = late.0.recordStartSucceeded(
      generation: late.1,
      handle: lateHandle,
      atMonotonicNanoseconds: deadline + 1
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(
      directive.effects,
      [
        StageBLifecycleEffect(
          generation: late.1,
          action: .stopEngineHandle(lateHandle)
        )
      ] + cancelEffects(late.1) + [
        StageBLifecycleEffect(
          generation: late.1,
          action: .runCleanup(
            byMonotonicNanoseconds: deadline + 1 + cleanupBudget
          )
        )
      ]
    )
    let recorded = late.0.snapshot()
    XCTAssertEqual(recorded.state, .terminal)
    XCTAssertEqual(recorded.terminalReason, .deadlineExceeded)
    XCTAssertFalse(
      recorded.engineHandleOwned,
      "a handle that arrived past its own budget is never adopted"
    )
  }

  func testSecondDistinctHandleFailsClosedAndStopsTheNewcomer() throws {
    let (machine, generation) = try started()
    let first = try StageBLifecycleEngineHandle(3)
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: first,
      atMonotonicNanoseconds: t0 + 5
    )
    let second = try StageBLifecycleEngineHandle(4)
    let directive = machine.recordStartSucceeded(
      generation: generation,
      handle: second,
      atMonotonicNanoseconds: t0 + 50
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(
      directive.effects,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(second)
        )
      ] + cancelEffects(generation) + [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(first)
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 50 + cleanupBudget
          )
        ),
      ]
    )
    XCTAssertEqual(machine.snapshot().terminalReason, .engineChanged)
    XCTAssertFalse(machine.snapshot().engineHandleOwned)
  }

  func testDuplicateStartSuccessWithTheSameHandleIsIdempotent() throws {
    let (machine, generation) = try started()
    let handle = try StageBLifecycleEngineHandle(3)
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: handle,
      atMonotonicNanoseconds: t0 + 5
    )
    let running = machine.snapshot()
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: generation,
        handle: handle,
        atMonotonicNanoseconds: t0 + 60
      ),
      StageBLifecycleDirective(
        disposition: .ignoredDuplicate,
        state: .running,
        terminalReason: nil,
        effects: []
      ),
      "the live handle must never be stopped by a duplicate callback"
    )
    XCTAssertEqual(machine.snapshot(), running)
  }

  func testStartFailedAfterStartSucceededFailsClosed() throws {
    let (machine, generation) = try started()
    let handle = try StageBLifecycleEngineHandle(8)
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: handle,
      atMonotonicNanoseconds: t0 + 5
    )
    let directive = machine.recordStartFailed(
      generation: generation,
      atMonotonicNanoseconds: t0 + 30
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(
      directive.effects,
      cancelEffects(generation) + [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(handle)
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 30 + cleanupBudget
          )
        ),
      ]
    )
    XCTAssertEqual(machine.snapshot().terminalReason, .startFailed)
    XCTAssertFalse(machine.snapshot().engineHandleOwned)
  }

  func testStartFailedBeforeAnyHandleIsAcceptedAndCleansUp() throws {
    let (machine, generation) = try started()
    let directive = machine.recordStartFailed(
      generation: generation,
      atMonotonicNanoseconds: t0 + 30
    )
    XCTAssertEqual(directive.disposition, .accepted)
    XCTAssertEqual(
      directive.effects,
      cancelEffects(generation) + [
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 30 + cleanupBudget
          )
        )
      ]
    )
    XCTAssertEqual(machine.snapshot().terminalReason, .startFailed)
  }

  // MARK: clock rollback

  func testTimerRollbackBelowTheWatermarkFailsClosed() throws {
    let machine = StageBProviderLifecycle()
    let generation = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x21),
      sequence: 1
    )
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0 + 100
    )
    let directive = machine.handleDeadlineTimerFired(
      generation: generation,
      atMonotonicNanoseconds: t0 + 50
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(directive.terminalReason, .clockRollback)
    let recorded = machine.snapshot()
    XCTAssertEqual(
      recorded.terminalAtMonotonicNanoseconds,
      t0 + 100,
      "the last trusted instant is recorded, not the rolled-back reading"
    )
    XCTAssertEqual(
      recorded.cleanupDeadlineMonotonicNanoseconds,
      t0 + 100 + cleanupBudget
    )
    XCTAssertEqual(
      machine.handleDeadlineTimerFired(
        generation: generation,
        atMonotonicNanoseconds: t0 + 200
      ).disposition,
      .ignoredTerminal
    )
    XCTAssertEqual(machine.snapshot(), recorded)
  }

  func testInstantBeyondTheAdmissibleCeilingFailsClosed() throws {
    let (machine, generation) = try started()
    // The ceiling is the deadline plus one stalled-wake budget plus one
    // cleanup budget.
    let ceiling = deadline + 2 * cleanupBudget
    let directive = machine.recordTerminal(
      generation: generation,
      reason: .stopped,
      atMonotonicNanoseconds: ceiling + 1
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(directive.terminalReason, .clockOutOfRange)
    XCTAssertEqual(
      machine.snapshot().terminalAtMonotonicNanoseconds,
      ceiling,
      "an out-of-range reading is never recorded as an observation"
    )

    let atCeiling = try started()
    let accepted = atCeiling.0.recordTerminal(
      generation: atCeiling.1,
      reason: .stopped,
      atMonotonicNanoseconds: ceiling
    )
    XCTAssertEqual(accepted.disposition, .rejected)
    XCTAssertEqual(
      accepted.terminalReason,
      .deadlineExceeded,
      "at the ceiling the clock is trusted and the deadline decides"
    )
    XCTAssertEqual(
      atCeiling.0.snapshot().terminalAtMonotonicNanoseconds,
      ceiling
    )
  }

  // MARK: exactly-once cleanup

  func testCleanupDirectiveIsEmittedExactlyOncePerGeneration() throws {
    let (machine, generation) = try started()
    _ = machine.recordStartSucceeded(
      generation: generation,
      handle: try StageBLifecycleEngineHandle(1),
      atMonotonicNanoseconds: t0 + 5
    )
    var directives = [StageBLifecycleDirective]()
    directives.append(
      machine.recordTerminal(
        generation: generation,
        reason: .pathChanged,
        atMonotonicNanoseconds: t0 + 500
      )
    )
    directives.append(
      machine.recordTerminal(
        generation: generation,
        reason: .stopped,
        atMonotonicNanoseconds: t0 + 600
      )
    )
    directives.append(
      machine.recordStartFailed(
        generation: generation,
        atMonotonicNanoseconds: t0 + 700
      )
    )
    directives.append(
      machine.handleDeadlineTimerFired(
        generation: generation,
        atMonotonicNanoseconds: deadline + 1
      )
    )
    directives.append(
      machine.recordStartSucceeded(
        generation: generation,
        handle: try StageBLifecycleEngineHandle(2),
        atMonotonicNanoseconds: deadline + 2
      )
    )
    directives.append(
      machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: t0 + 500 + cleanupBudget
      )
    )
    directives.append(
      machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: t0 + 500 + cleanupBudget
      )
    )

    let cleanupDirectives = directives.flatMap(\.effects).filter {
      if case .runCleanup = $0.action { return true }
      return false
    }
    XCTAssertEqual(
      cleanupDirectives,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 500 + cleanupBudget
          )
        )
      ]
    )
    XCTAssertEqual(machine.snapshot().cleanupDirectivesEmitted, 1)
    XCTAssertEqual(machine.snapshot().terminalReason, .pathChanged)
    let stops = directives.flatMap(\.effects).filter {
      if case .stopEngineHandle = $0.action { return true }
      return false
    }
    XCTAssertEqual(
      stops,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(
            try StageBLifecycleEngineHandle(1)
          )
        ),
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(
            try StageBLifecycleEngineHandle(2)
          )
        ),
      ],
      "the adopted handle and the late orphan are each stopped once"
    )
  }

  func testCleanupIsAcceptedOnceAtTheExactBudgetBoundary() throws {
    let (machine, generation) = try started()
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 1_000
    )
    let cleanupDeadline = t0 + 1_000 + cleanupBudget
    XCTAssertEqual(
      machine.snapshot().cleanupDeadlineMonotonicNanoseconds,
      cleanupDeadline
    )
    XCTAssertEqual(
      machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: cleanupDeadline
      ),
      StageBLifecycleDirective(
        disposition: .accepted,
        state: .cleaned,
        terminalReason: .cancelled,
        effects: []
      )
    )
    let cleaned = machine.snapshot()
    XCTAssertEqual(cleaned.cleanupState, .completedWithinBudget)
    XCTAssertEqual(
      cleaned.cleanupCompletedAtMonotonicNanoseconds,
      cleanupDeadline
    )

    XCTAssertEqual(
      machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: cleanupDeadline + 5
      ).disposition,
      .ignoredDuplicate
    )
    XCTAssertEqual(
      machine.snapshot(),
      cleaned,
      "a second cleanup completion changes nothing"
    )
  }

  func testCleanupOneNanosecondPastTheBudgetIsOverBudget() throws {
    let (machine, generation) = try started()
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 1_000
    )
    let directive = machine.recordCleanupCompleted(
      generation: generation,
      atMonotonicNanoseconds: t0 + 1_000 + cleanupBudget + 1
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(
      machine.snapshot().cleanupState,
      .completedOverBudget
    )
    XCTAssertEqual(machine.snapshot().state, .cleaned)

    let early = try started()
    _ = early.0.recordTerminal(
      generation: early.1,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 1_000
    )
    XCTAssertEqual(
      early.0.recordCleanupCompleted(
        generation: early.1,
        atMonotonicNanoseconds: t0 + 999
      ).disposition,
      .rejected,
      "cleanup cannot finish before the terminal it follows"
    )
    XCTAssertEqual(
      early.0.snapshot().cleanupState,
      .completedOutOfOrder,
      "an instant before the terminal is untrusted, not merely late"
    )
    XCTAssertEqual(
      early.0.snapshot().cleanupCompletedAtMonotonicNanoseconds,
      t0 + 1_000
    )
  }

  func testCleanupBeforeAnyTerminalRecordsNothing() throws {
    let (machine, generation) = try started()
    let before = machine.snapshot()
    XCTAssertEqual(
      machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: t0 + 10
      ),
      StageBLifecycleDirective(
        disposition: .ignoredNotApplicable,
        state: .starting,
        terminalReason: nil,
        effects: []
      )
    )
    XCTAssertEqual(machine.snapshot(), before)
    XCTAssertEqual(before.cleanupState, .notStarted)
  }

  // MARK: (1) success requires a running engine

  func testSuccessRequiresARunningAttemptThatOwnsItsHandle() throws {
    // Requested from `starting`, before any wgTurnOn has returned.
    let (machine, generation) = try started()
    let directive = machine.recordTerminal(
      generation: generation,
      reason: .succeeded,
      atMonotonicNanoseconds: t0 + 10
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(
      directive.terminalReason,
      .successWithoutRunningEngine
    )
    XCTAssertEqual(
      directive.effects,
      cancelEffects(generation) + [
        StageBLifecycleEffect(
          generation: generation,
          action: .runCleanup(
            byMonotonicNanoseconds: t0 + 10 + cleanupBudget
          )
        )
      ],
      "a success with no engine is torn down like any other failure"
    )
    let recorded = machine.snapshot()
    XCTAssertEqual(
      recorded.terminalReason,
      .successWithoutRunningEngine
    )
    XCTAssertFalse(recorded.engineHandleOwned)
    XCTAssertEqual(recorded.cleanupState, .pending)
    XCTAssertEqual(recorded.cleanupDirectivesEmitted, 1)

    // The same request from a running attempt that owns its handle stands.
    let running = try startedRunning()
    let accepted = running.0.recordTerminal(
      generation: running.1,
      reason: .succeeded,
      atMonotonicNanoseconds: t0 + 10
    )
    XCTAssertEqual(accepted.disposition, .accepted)
    XCTAssertEqual(accepted.terminalReason, .succeeded)
    XCTAssertTrue(running.0.snapshot().engineHandleOwned)
    XCTAssertEqual(
      running.0.snapshot().cleanupState,
      .notRequired
    )
  }

  // MARK: (2) the retained handle is never torn down

  func testDuplicateStartSuccessAfterSuccessNeverStopsTheLiveTunnel()
    throws
  {
    let (machine, generation) = try startedRunning(handleValue: 3)
    let live = try StageBLifecycleEngineHandle(3)
    _ = machine.recordTerminal(
      generation: generation,
      reason: .succeeded,
      atMonotonicNanoseconds: t0 + 50
    )
    let succeeded = machine.snapshot()
    XCTAssertTrue(succeeded.engineHandleOwned)

    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: generation,
        handle: live,
        atMonotonicNanoseconds: t0 + 60
      ),
      StageBLifecycleDirective(
        disposition: .ignoredDuplicate,
        state: .terminal,
        terminalReason: .succeeded,
        effects: []
      ),
      "the handle a success retains must never be stopped"
    )
    XCTAssertEqual(machine.snapshot(), succeeded)

    // A genuinely distinct newcomer after the same success is still stopped.
    let newcomer = try StageBLifecycleEngineHandle(4)
    let directive = machine.recordStartSucceeded(
      generation: generation,
      handle: newcomer,
      atMonotonicNanoseconds: t0 + 70
    )
    XCTAssertEqual(directive.disposition, .ignoredTerminal)
    XCTAssertEqual(
      directive.effects,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(newcomer)
        )
      ]
    )
    XCTAssertTrue(
      machine.snapshot().engineHandleOwned,
      "stopping the newcomer must not disown the live handle"
    )
    XCTAssertEqual(machine.snapshot().terminalReason, .succeeded)
  }

  func testConcurrentDuplicateStartSuccessNeverStopsTheRetainedHandle()
    throws
  {
    let (machine, generation) = try startedRunning(handleValue: 3)
    let live = try StageBLifecycleEngineHandle(3)
    let newcomer = try StageBLifecycleEngineHandle(4)
    _ = machine.recordTerminal(
      generation: generation,
      reason: .succeeded,
      atMonotonicNanoseconds: t0 + 50
    )
    let results = LockedDirectives()
    DispatchQueue.concurrentPerform(iterations: 64) { index in
      results.append(
        machine.recordStartSucceeded(
          generation: generation,
          handle: index.isMultiple(of: 2) ? live : newcomer,
          atMonotonicNanoseconds: t0 + 60
        )
      )
    }
    let stops = results.value.flatMap(\.effects).filter {
      if case .stopEngineHandle = $0.action { return true }
      return false
    }
    XCTAssertEqual(
      stops,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(newcomer)
        )
      ],
      "exactly one stop, and never for the retained handle"
    )
    XCTAssertTrue(machine.snapshot().engineHandleOwned)
    XCTAssertEqual(machine.snapshot().terminalReason, .succeeded)
  }

  // MARK: (3) raw-handle aliasing across generations

  func testAliasedStaleHandleNeverStopsTheLiveEngine() throws {
    let machine = StageBProviderLifecycle()
    let first = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x21),
      sequence: 1
    )
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    _ = machine.recordTerminal(
      generation: first,
      reason: .superseded,
      atMonotonicNanoseconds: t0 + 10
    )
    _ = machine.recordCleanupCompleted(
      generation: first,
      atMonotonicNanoseconds: t0 + 20
    )
    let secondT0 = t0 + 1_000_000_000
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x31),
      t0MonotonicNanoseconds: secondT0,
      atMonotonicNanoseconds: secondT0
    )
    let second = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: 2
    )
    // The operating system hands generation two the very value generation
    // one's engine used.
    let shared = try StageBLifecycleEngineHandle(7)
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: second,
        handle: shared,
        atMonotonicNanoseconds: secondT0 + 5
      ).disposition,
      .accepted
    )

    let late = machine.recordStartSucceeded(
      generation: first,
      handle: shared,
      atMonotonicNanoseconds: secondT0 + 10
    )
    XCTAssertEqual(late.disposition, .rejected)
    XCTAssertEqual(late.terminalReason, .engineHandleAliased)
    XCTAssertFalse(
      late.effects.contains(
        StageBLifecycleEffect(
          generation: first,
          action: .stopEngineHandle(shared)
        )
      ),
      "an ambiguous Int32 is never stopped on the stale generation's behalf"
    )
    XCTAssertEqual(
      late.effects,
      cancelEffects(second) + [
        StageBLifecycleEffect(
          generation: second,
          action: .stopEngineHandle(shared)
        ),
        StageBLifecycleEffect(
          generation: second,
          action: .runCleanup(
            byMonotonicNanoseconds:
              secondT0 + 10 + cleanupBudget
          )
        ),
      ],
      "the only stop names the generation that actually owns the value"
    )
    let recorded = machine.snapshot()
    XCTAssertEqual(recorded.aliasedEngineHandleReports, 1)
    XCTAssertEqual(recorded.terminalReason, .engineHandleAliased)
    XCTAssertFalse(recorded.engineHandleOwned)
    XCTAssertEqual(recorded.outstandingEngineHandleStops, 1)
  }

  func testAdoptingAValueUnderAnOutstandingStopFailsClosed() throws {
    let (machine, generation) = try started()
    let stale = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: 9
    )
    let shared = try StageBLifecycleEngineHandle(5)
    // A stale generation's late turn-on claims value 5 while this attempt is
    // still starting, so a stop for 5 is outstanding.
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: stale,
        handle: shared,
        atMonotonicNanoseconds: t0 + 5
      ).effects,
      [
        StageBLifecycleEffect(
          generation: stale,
          action: .stopEngineHandle(shared)
        )
      ]
    )
    XCTAssertEqual(machine.snapshot().outstandingEngineHandleStops, 1)

    // This attempt's own wgTurnOn now returns the same raw value.
    let directive = machine.recordStartSucceeded(
      generation: generation,
      handle: shared,
      atMonotonicNanoseconds: t0 + 10
    )
    XCTAssertEqual(directive.disposition, .rejected)
    XCTAssertEqual(directive.terminalReason, .engineHandleAliased)
    XCTAssertFalse(
      machine.snapshot().engineHandleOwned,
      "an ambiguous value is never adopted"
    )
    XCTAssertEqual(machine.snapshot().aliasedEngineHandleReports, 1)

    // Once the outstanding stop is confirmed the value is unambiguous again.
    let fresh = StageBProviderLifecycle()
    _ = try fresh.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    let freshGeneration = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x21),
      sequence: 1
    )
    _ = fresh.recordStartSucceeded(
      generation: stale,
      handle: shared,
      atMonotonicNanoseconds: t0 + 5
    )
    XCTAssertEqual(
      fresh.recordEngineHandleStopped(
        generation: stale,
        handle: shared
      ).disposition,
      .accepted
    )
    XCTAssertEqual(fresh.snapshot().outstandingEngineHandleStops, 0)
    XCTAssertEqual(
      fresh.recordStartSucceeded(
        generation: freshGeneration,
        handle: shared,
        atMonotonicNanoseconds: t0 + 10
      ).disposition,
      .accepted
    )
    XCTAssertTrue(fresh.snapshot().engineHandleOwned)
  }

  func testTwoStaleGenerationsCannotBothClaimOneRawValue() throws {
    let (machine, _) = try started()
    let shared = try StageBLifecycleEngineHandle(5)
    let firstClaimant = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x41),
      sequence: 9
    )
    let secondClaimant = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x51),
      sequence: 8
    )
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: firstClaimant,
        handle: shared,
        atMonotonicNanoseconds: t0 + 5
      ).effects,
      [
        StageBLifecycleEffect(
          generation: firstClaimant,
          action: .stopEngineHandle(shared)
        )
      ]
    )

    // A different abandoned generation reports the very same raw value while
    // the first stop is still unconfirmed. One Int32 cannot name two engines.
    let contested = machine.recordStartSucceeded(
      generation: secondClaimant,
      handle: shared,
      atMonotonicNanoseconds: t0 + 6
    )
    XCTAssertEqual(contested.disposition, .rejected)
    XCTAssertEqual(contested.terminalReason, .engineHandleAliased)
    XCTAssertFalse(
      contested.effects.contains(
        StageBLifecycleEffect(
          generation: secondClaimant,
          action: .stopEngineHandle(shared)
        )
      ),
      "a second claimant on one raw value must never be stopped"
    )
    let recorded = machine.snapshot()
    XCTAssertEqual(
      recorded.outstandingEngineHandleStops,
      1,
      "exactly one stop is outstanding for the contested value"
    )
    XCTAssertEqual(recorded.aliasedEngineHandleReports, 1)
    XCTAssertEqual(recorded.terminalReason, .engineHandleAliased)
  }

  func testConcurrentClaimantsOnOneRawValueYieldOneStop() throws {
    let (machine, _) = try started()
    let shared = try StageBLifecycleEngineHandle(5)
    let results = LockedDirectives()
    DispatchQueue.concurrentPerform(iterations: 32) { index in
      guard
        let generation = try? StageBLifecycleGeneration(
          attemptNonce: lifecycleUUID(UInt8(0x40 + index)),
          sequence: UInt64(index + 2)
        )
      else {
        return XCTFail("generation \(index) could not be built")
      }
      results.append(
        machine.recordStartSucceeded(
          generation: generation,
          handle: shared,
          atMonotonicNanoseconds: t0 + 5
        )
      )
    }
    let stops = results.value.flatMap(\.effects).filter {
      if case let .stopEngineHandle(handle) = $0.action {
        return handle == shared
      }
      return false
    }
    XCTAssertEqual(results.value.count, 32)
    XCTAssertEqual(
      stops.count,
      1,
      "32 concurrent claimants on one raw value produce one stop"
    )
    XCTAssertEqual(
      machine.snapshot().outstandingEngineHandleStops,
      1
    )
    XCTAssertEqual(
      machine.snapshot().terminalReason,
      .engineHandleAliased
    )
  }

  func testStopConfirmationIsExactAndBoundedToItsGeneration() throws {
    let (machine, generation) = try startedRunning(handleValue: 6)
    let handle = try StageBLifecycleEngineHandle(6)
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 100
    )
    XCTAssertEqual(machine.snapshot().outstandingEngineHandleStops, 1)

    let impostor = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: 1
    )
    XCTAssertEqual(
      machine.recordEngineHandleStopped(
        generation: impostor,
        handle: handle
      ).disposition,
      .ignoredStaleGeneration
    )
    XCTAssertEqual(machine.snapshot().outstandingEngineHandleStops, 1)

    XCTAssertEqual(
      machine.recordEngineHandleStopped(
        generation: generation,
        handle: handle
      ).disposition,
      .accepted
    )
    XCTAssertEqual(machine.snapshot().outstandingEngineHandleStops, 0)
    XCTAssertEqual(
      machine.recordEngineHandleStopped(
        generation: generation,
        handle: handle
      ).disposition,
      .ignoredDuplicate
    )
    XCTAssertEqual(machine.snapshot().outstandingEngineHandleStops, 0)
  }

  func testANewAttemptCannotBeginWhileAStopIsOutstanding() throws {
    let (machine, generation) = try startedRunning(handleValue: 6)
    let handle = try StageBLifecycleEngineHandle(6)
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 100
    )
    _ = machine.recordCleanupCompleted(
      generation: generation,
      atMonotonicNanoseconds: t0 + 200
    )
    XCTAssertEqual(machine.snapshot().state, .cleaned)

    let retryT0 = t0 + 1_000_000_000
    XCTAssertThrowsError(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: retryT0,
        atMonotonicNanoseconds: retryT0
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .engineHandleStopOutstanding
      )
    }
    _ = machine.recordEngineHandleStopped(
      generation: generation,
      handle: handle
    )
    XCTAssertNoThrow(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: retryT0,
        atMonotonicNanoseconds: retryT0
      )
    )
  }

  func testTheSameOrphanPairIsNeverStoppedTwice() throws {
    let (machine, generation) = try started()
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 10
    )
    let orphan = try StageBLifecycleEngineHandle(9)
    let first = machine.recordStartSucceeded(
      generation: generation,
      handle: orphan,
      atMonotonicNanoseconds: t0 + 20
    )
    XCTAssertEqual(
      first.effects,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .stopEngineHandle(orphan)
        )
      ]
    )
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: generation,
        handle: orphan,
        atMonotonicNanoseconds: t0 + 30
      ),
      StageBLifecycleDirective(
        disposition: .ignoredDuplicate,
        state: .terminal,
        terminalReason: .cancelled,
        effects: []
      ),
      "a repeated report cannot direct a second stop for one handle"
    )
    XCTAssertEqual(machine.snapshot().outstandingEngineHandleStops, 1)
    XCTAssertEqual(machine.snapshot().staleEngineHandleStopsDirected, 1)
  }

  // MARK: cross-generation chronology

  func testANewT0CannotPredateTheTrustedWatermark() throws {
    // Every case starts from a machine whose watermark is t0 + 20: the
    // cleanup completion at that instant was accepted and recorded.
    func cleanedMachine() throws -> StageBProviderLifecycle {
      let (machine, generation) = try started()
      _ = machine.recordTerminal(
        generation: generation,
        reason: .cancelled,
        atMonotonicNanoseconds: t0 + 10
      )
      _ = machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: t0 + 20
      )
      XCTAssertEqual(machine.snapshot().state, .cleaned)
      return machine
    }
    let watermark = t0 + 20

    let below = try cleanedMachine()
    XCTAssertThrowsError(
      try below.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: watermark - 1,
        atMonotonicNanoseconds: watermark
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .invalidDeadline,
        "a first click cannot predate a recorded observation"
      )
    }
    XCTAssertEqual(
      below.snapshot().generation?.sequence,
      1,
      "the refused attempt minted no generation"
    )

    let exactly = try cleanedMachine()
    let atWatermark = try exactly.beginAttempt(
      attemptNonce: lifecycleUUID(0x31),
      t0MonotonicNanoseconds: watermark,
      atMonotonicNanoseconds: watermark
    )
    XCTAssertEqual(atWatermark.disposition, .accepted)
    XCTAssertEqual(
      exactly.snapshot().t0MonotonicNanoseconds,
      watermark
    )
    XCTAssertEqual(
      exactly.snapshot().deadlineMonotonicNanoseconds,
      watermark + successBudget
    )

    let above = try cleanedMachine()
    XCTAssertEqual(
      try above.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: watermark + 1,
        atMonotonicNanoseconds: watermark + 1
      ).disposition,
      .accepted
    )
    XCTAssertEqual(
      above.snapshot().deadlineMonotonicNanoseconds,
      watermark + 1 + successBudget
    )
  }

  func testT0MustAlsoStrictlyFollowThePreviousFirstClick() throws {
    // A whole cycle at one instant leaves the watermark equal to T0, so the
    // watermark rule alone would admit a replayed first click.
    let machine = StageBProviderLifecycle()
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    let generation = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x21),
      sequence: 1
    )
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0
    )
    _ = machine.recordCleanupCompleted(
      generation: generation,
      atMonotonicNanoseconds: t0
    )
    XCTAssertEqual(
      machine.snapshot().terminalAtMonotonicNanoseconds,
      t0,
      "the watermark and the previous T0 now coincide"
    )
    XCTAssertThrowsError(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: t0,
        atMonotonicNanoseconds: t0
      )
    ) {
      XCTAssertEqual($0 as? StageBLifecycleError, .invalidDeadline)
    }
    XCTAssertEqual(
      try machine.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: t0 + 1,
        atMonotonicNanoseconds: t0 + 1
      ).disposition,
      .accepted
    )
  }

  // MARK: stop tombstones survive a generation boundary

  func testAConfirmedStopIsNotReissuedAfterANewAttemptBegins() throws {
    let (machine, first) = try startedRunning(handleValue: 5)
    let shared = try StageBLifecycleEngineHandle(5)
    _ = machine.recordTerminal(
      generation: first,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 10
    )
    XCTAssertEqual(
      machine.recordEngineHandleStopped(
        generation: first,
        handle: shared
      ).disposition,
      .accepted
    )
    _ = machine.recordCleanupCompleted(
      generation: first,
      atMonotonicNanoseconds: t0 + 20
    )
    let secondT0 = t0 + 1_000_000_000
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0x31),
      t0MonotonicNanoseconds: secondT0,
      atMonotonicNanoseconds: secondT0
    )
    let second = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x31),
      sequence: 2
    )
    XCTAssertEqual(
      machine.snapshot().outstandingEngineHandleStops,
      0,
      "confirmation cleared the outstanding flag"
    )

    // The already-confirmed callback arrives a second time. The tombstone,
    // not the outstanding flag, is what must refuse it.
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: first,
        handle: shared,
        atMonotonicNanoseconds: secondT0 + 1
      ),
      StageBLifecycleDirective(
        disposition: .ignoredDuplicate,
        state: .starting,
        terminalReason: nil,
        effects: []
      ),
      "a confirmed stop is never reissued for a recycled value"
    )
    XCTAssertEqual(
      machine.snapshot().outstandingEngineHandleStops,
      0
    )

    // The new generation may therefore still adopt the recycled value.
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: second,
        handle: shared,
        atMonotonicNanoseconds: secondT0 + 2
      ).disposition,
      .accepted,
      "the recycled value is unambiguous, so the new engine is adopted"
    )
    XCTAssertTrue(machine.snapshot().engineHandleOwned)
    XCTAssertNil(machine.snapshot().terminalReason)
    XCTAssertEqual(machine.snapshot().aliasedEngineHandleReports, 0)
  }

  func testTheStopLedgerIsBoundedAndRefusesWhatItForgets() throws {
    let capacity = 128
    XCTAssertEqual(
      StageBProviderLifecycle.stopLedgerCapacity,
      capacity
    )
    // A live generation far above every stale one, so eviction always has an
    // older entry to take.
    let machine = StageBProviderLifecycle(
      nextGenerationSequence: 1_000
    )
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0xf1),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    let live = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0xf1),
      sequence: 1_000
    )

    func staleReport(_ index: Int) throws -> StageBLifecycleDirective {
      machine.recordStartSucceeded(
        generation: try StageBLifecycleGeneration(
          attemptNonce: lifecycleUUID(UInt8(index)),
          sequence: UInt64(index)
        ),
        handle: try StageBLifecycleEngineHandle(Int32(index)),
        atMonotonicNanoseconds: t0 + 1
      )
    }

    for index in 1...capacity {
      XCTAssertEqual(
        try staleReport(index).effects.count,
        1,
        "stale report \(index) fills one ledger slot"
      )
    }
    XCTAssertEqual(machine.snapshot().stopLedgerHorizonSequence, 0)
    XCTAssertEqual(
      machine.snapshot().staleEngineHandleStopsDirected,
      capacity
    )

    // One past capacity evicts the oldest entry and raises the horizon.
    XCTAssertEqual(try staleReport(capacity + 1).effects.count, 1)
    XCTAssertEqual(machine.snapshot().stopLedgerHorizonSequence, 1)

    // The evicted generation can no longer be stopped: the machine cannot
    // prove it has not already been.
    let forgotten = try staleReport(1)
    XCTAssertEqual(forgotten.disposition, .rejected)
    XCTAssertEqual(
      forgotten.effects,
      [],
      "a forgotten generation is refused, never stopped on a guess"
    )
    XCTAssertEqual(
      machine.snapshot().unattributableStaleHandleReports,
      1
    )
    XCTAssertEqual(
      machine.snapshot().state,
      .starting,
      "refusing a forgotten report leaves the live attempt alone"
    )
    XCTAssertNil(machine.snapshot().terminalReason)

    // Saturation never makes the live attempt's own handle unstoppable.
    let owned = try StageBLifecycleEngineHandle(9_999)
    XCTAssertEqual(
      machine.recordStartSucceeded(
        generation: live,
        handle: owned,
        atMonotonicNanoseconds: t0 + 2
      ).disposition,
      .accepted
    )
    let terminal = machine.recordTerminal(
      generation: live,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 3
    )
    XCTAssertTrue(
      terminal.effects.contains(
        StageBLifecycleEffect(
          generation: live,
          action: .stopEngineHandle(owned)
        )
      ),
      "the live attempt's own handle is always stoppable"
    )
    XCTAssertLessThan(
      machine.snapshot().stopLedgerHorizonSequence,
      live.sequence
    )
  }

  func testEvictionNeverForgetsTheLiveGenerationsOwnStops() throws {
    let capacity = 128
    let machine = StageBProviderLifecycle(
      nextGenerationSequence: 1_000
    )
    _ = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(0xf1),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    let live = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0xf1),
      sequence: 1_000
    )
    // The live generation's own tombstone is the FIRST ledger entry, so it
    // sits at the head of the eviction queue.
    let owned = try StageBLifecycleEngineHandle(9_999)
    _ = machine.recordStartSucceeded(
      generation: live,
      handle: owned,
      atMonotonicNanoseconds: t0 + 1
    )
    _ = machine.recordTerminal(
      generation: live,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 2
    )

    func staleReport(_ index: Int) throws -> StageBLifecycleDirective {
      machine.recordStartSucceeded(
        generation: try StageBLifecycleGeneration(
          attemptNonce: lifecycleUUID(UInt8(index)),
          sequence: UInt64(index)
        ),
        handle: try StageBLifecycleEngineHandle(Int32(index)),
        atMonotonicNanoseconds: t0 + 3
      )
    }
    // Fill the remaining slots, then force one eviction. A report bearing a
    // sequence far above the live one must not raise the eviction bar.
    for index in 1...(capacity - 1) {
      XCTAssertEqual(try staleReport(index).effects.count, 1)
    }
    let intruder = machine.recordStartSucceeded(
      generation: try StageBLifecycleGeneration(
        attemptNonce: lifecycleUUID(0xfe),
        sequence: UInt64.max
      ),
      handle: try StageBLifecycleEngineHandle(8_888),
      atMonotonicNanoseconds: t0 + 4
    )
    XCTAssertEqual(intruder.effects.count, 1)
    XCTAssertEqual(
      machine.snapshot().stopLedgerHorizonSequence,
      1,
      "the oldest stale entry was evicted, not the live generation's"
    )
    XCTAssertLessThan(
      machine.snapshot().stopLedgerHorizonSequence,
      live.sequence
    )

    // Decisive check: the live generation is still stoppable.
    let another = try StageBLifecycleEngineHandle(7_777)
    let directive = machine.recordStartSucceeded(
      generation: live,
      handle: another,
      atMonotonicNanoseconds: t0 + 5
    )
    XCTAssertEqual(
      directive.effects,
      [
        StageBLifecycleEffect(
          generation: live,
          action: .stopEngineHandle(another)
        )
      ],
      "the live generation must never fall below the ledger horizon"
    )
    XCTAssertEqual(
      machine.snapshot().unattributableStaleHandleReports,
      0
    )
  }

  // MARK: (4) derived reasons are not caller-assertable

  func testRequestedReasonsCannotCarryDerivedConditions() {
    let requestable: [StageBLifecycleRequestedTerminalReason] = [
      .succeeded, .stopped, .cancelled, .superseded, .pathChanged,
      .engineChanged, .networkSettingsChanged, .bindingMismatch,
    ]
    XCTAssertEqual(
      StageBLifecycleRequestedTerminalReason.allCases.count,
      requestable.count,
      "a new requestable reason must be reviewed here"
    )
    for reason in requestable {
      XCTAssertTrue(
        reason.recorded.isCallerAssertable,
        "\(reason) maps onto a derived-only outcome"
      )
      XCTAssertEqual(reason.recorded.rawValue, reason.rawValue)
    }
    let derived: [StageBLifecycleTerminalReason] = [
      .startFailed, .deadlineExceeded, .clockRollback,
      .clockOutOfRange, .successWithoutRunningEngine,
      .engineHandleAliased,
    ]
    for reason in derived {
      XCTAssertFalse(
        reason.isCallerAssertable,
        "\(reason) is derived and must never be requestable"
      )
      XCTAssertFalse(
        requestable.map(\.recorded).contains(reason),
        "\(reason) is reachable from a requested reason"
      )
    }
  }

  // MARK: (5) truthful cleanup timestamps

  func testCleanupInstantBeforeTheTerminalIsClampedAndRejected() throws {
    let (machine, generation) = try started()
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 1_000
    )
    let directive = machine.recordCleanupCompleted(
      generation: generation,
      atMonotonicNanoseconds: 0
    )
    XCTAssertEqual(directive.disposition, .rejected)
    let recorded = machine.snapshot()
    XCTAssertEqual(
      recorded.cleanupState,
      .completedOutOfOrder,
      "an untrusted instant is never reported as merely over budget"
    )
    XCTAssertEqual(
      recorded.cleanupCompletedAtMonotonicNanoseconds,
      t0 + 1_000,
      "the recorded instant is clamped to the terminal decision"
    )
    XCTAssertEqual(recorded.state, .cleaned)
    XCTAssertEqual(
      machine.recordCleanupCompleted(
        generation: generation,
        atMonotonicNanoseconds: t0 + 1_100
      ).disposition,
      .ignoredDuplicate
    )
    XCTAssertEqual(machine.snapshot(), recorded)
  }

  func testCleanupInstantBeyondTheCeilingIsClampedAndRejected() throws {
    let (machine, generation) = try started()
    _ = machine.recordTerminal(
      generation: generation,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 1_000
    )
    let ceiling = deadline + 2 * cleanupBudget
    let directive = machine.recordCleanupCompleted(
      generation: generation,
      atMonotonicNanoseconds: UInt64.max
    )
    XCTAssertEqual(directive.disposition, .rejected)
    let recorded = machine.snapshot()
    XCTAssertEqual(recorded.cleanupState, .completedOutOfOrder)
    XCTAssertEqual(
      recorded.cleanupCompletedAtMonotonicNanoseconds,
      ceiling,
      "the recorded instant is clamped to the attempt's frozen ceiling"
    )
  }

  // MARK: (6) bounded generation sequence

  func testGenerationSequenceExhaustionFailsClosed() throws {
    let exhausted = StageBProviderLifecycle(
      nextGenerationSequence: UInt64.max
    )
    XCTAssertThrowsError(
      try exhausted.beginAttempt(
        attemptNonce: lifecycleUUID(0x21),
        t0MonotonicNanoseconds: t0,
        atMonotonicNanoseconds: t0
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .generationSpaceExhausted
      )
    }
    XCTAssertEqual(
      exhausted.snapshot().state,
      .idle,
      "the exhausted machine records no attempt"
    )

    // One below the ceiling still mints exactly one generation.
    let last = StageBProviderLifecycle(
      nextGenerationSequence: UInt64.max - 1
    )
    _ = try last.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    let penultimate = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(0x21),
      sequence: UInt64.max - 1
    )
    XCTAssertEqual(last.snapshot().generation, penultimate)
    _ = last.recordTerminal(
      generation: penultimate,
      reason: .cancelled,
      atMonotonicNanoseconds: t0 + 10
    )
    _ = last.recordCleanupCompleted(
      generation: penultimate,
      atMonotonicNanoseconds: t0 + 20
    )
    XCTAssertThrowsError(
      try last.beginAttempt(
        attemptNonce: lifecycleUUID(0x31),
        t0MonotonicNanoseconds: t0 + 1_000_000_000,
        atMonotonicNanoseconds: t0 + 1_000_000_000
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBLifecycleError,
        .generationSpaceExhausted
      )
    }

    // A seed below one is raised rather than producing an invalid generation.
    let clamped = StageBProviderLifecycle(nextGenerationSequence: 0)
    _ = try clamped.beginAttempt(
      attemptNonce: lifecycleUUID(0x21),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    XCTAssertEqual(clamped.snapshot().generation?.sequence, 1)
  }

  // MARK: helpers

  private func startedRunning(
    nonce: UInt8 = 0x21,
    handleValue: Int32 = 3
  ) throws -> (StageBProviderLifecycle, StageBLifecycleGeneration) {
    let (machine, generation) = try started(nonce: nonce)
    let directive = machine.recordStartSucceeded(
      generation: generation,
      handle: try StageBLifecycleEngineHandle(handleValue),
      atMonotonicNanoseconds: t0 + 1
    )
    XCTAssertEqual(directive.disposition, .accepted)
    XCTAssertEqual(machine.snapshot().state, .running)
    return (machine, generation)
  }

  private func started(
    nonce: UInt8 = 0x21
  ) throws -> (StageBProviderLifecycle, StageBLifecycleGeneration) {
    let machine = StageBProviderLifecycle()
    let directive = try machine.beginAttempt(
      attemptNonce: lifecycleUUID(nonce),
      t0MonotonicNanoseconds: t0,
      atMonotonicNanoseconds: t0
    )
    let generation = try StageBLifecycleGeneration(
      attemptNonce: lifecycleUUID(nonce),
      sequence: 1
    )
    XCTAssertEqual(
      directive.effects,
      [
        StageBLifecycleEffect(
          generation: generation,
          action: .armDeadlineTimer(
            atMonotonicNanoseconds: t0 + successBudget + 1
          )
        )
      ]
    )
    return (machine, generation)
  }
}

/// The three cancellation scopes written out as literals, so a scope dropped
/// from the machine's terminal path cannot be masked by reading `allCases`
/// from the same enum the machine reads.
private func cancelEffects(
  _ generation: StageBLifecycleGeneration
) -> [StageBLifecycleEffect] {
  [
    StageBLifecycleEffect(
      generation: generation,
      action: .cancel(.timers)
    ),
    StageBLifecycleEffect(
      generation: generation,
      action: .cancel(.sockets)
    ),
    StageBLifecycleEffect(
      generation: generation,
      action: .cancel(.nativeWork)
    ),
  ]
}

private func lifecycleUUID(_ fill: UInt8) -> [UInt8] {
  var bytes = [UInt8](repeating: fill, count: 16)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  return bytes
}

private final class LockedDirectives: @unchecked Sendable {
  private let lock = NSLock()
  private var directives = [StageBLifecycleDirective]()

  var value: [StageBLifecycleDirective] {
    lock.lock()
    defer { lock.unlock() }
    return directives
  }

  func append(_ directive: StageBLifecycleDirective) {
    lock.lock()
    directives.append(directive)
    lock.unlock()
  }
}
