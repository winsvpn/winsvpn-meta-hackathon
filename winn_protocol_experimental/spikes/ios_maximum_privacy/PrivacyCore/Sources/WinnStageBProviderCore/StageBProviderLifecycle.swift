import Foundation
import WinnPrivacyCore

/// Inputs the lifecycle machine refuses outright instead of recording.
public enum StageBLifecycleError: Error, Equatable, Sendable {
  case invalidIdentifier
  case invalidGeneration
  case invalidHandle
  case invalidDeadline
  case invalidState
  case generationSpaceExhausted
  case engineHandleStopOutstanding
}

/// Lifecycle position of the one attempt owned by a provider instance.
///
/// `cleaned` is reachable only from a non-success terminal. A successful
/// attempt keeps its AWG handle because the tunnel must stay up, so it stops
/// at `terminal` and never reports `cleaned`.
public enum StageBLifecycleState: String, Equatable, Sendable {
  case idle
  case starting
  case running
  case terminal
  case cleaned
}

/// Terminal outcomes a caller is allowed to assert.
///
/// Every condition the machine derives for itself is deliberately absent:
/// expiry, an untrusted clock reading, a failed start, a success claimed
/// without a running engine, and raw-handle aliasing are observations, not
/// caller opinions. A caller therefore cannot label an attempt with a
/// condition the machine has not seen.
public enum StageBLifecycleRequestedTerminalReason:
  String, Equatable, Sendable, CaseIterable
{
  case succeeded
  case stopped
  case cancelled
  case superseded
  case pathChanged
  case engineChanged
  case networkSettingsChanged
  case bindingMismatch

  public var recorded: StageBLifecycleTerminalReason {
    switch self {
    case .succeeded: return .succeeded
    case .stopped: return .stopped
    case .cancelled: return .cancelled
    case .superseded: return .superseded
    case .pathChanged: return .pathChanged
    case .engineChanged: return .engineChanged
    case .networkSettingsChanged: return .networkSettingsChanged
    case .bindingMismatch: return .bindingMismatch
    }
  }
}

/// The single authoritative outcome recorded by the first terminal transition.
///
/// `isCallerAssertable` marks the outcomes a caller may request. The rest are
/// derived and can only be produced by the machine's own checks.
public enum StageBLifecycleTerminalReason: String, Equatable, Sendable {
  case succeeded
  case stopped
  case cancelled
  case superseded
  case pathChanged
  case engineChanged
  case networkSettingsChanged
  case bindingMismatch
  case startFailed
  case deadlineExceeded
  case clockRollback
  case clockOutOfRange
  case successWithoutRunningEngine
  case engineHandleAliased

  public var isCallerAssertable: Bool {
    switch self {
    case .succeeded, .stopped, .cancelled, .superseded, .pathChanged,
      .engineChanged, .networkSettingsChanged, .bindingMismatch:
      return true
    case .startFailed, .deadlineExceeded, .clockRollback,
      .clockOutOfRange, .successWithoutRunningEngine,
      .engineHandleAliased:
      return false
    }
  }
}

/// Cleanup accounting for the current generation.
///
/// The machine records a completion only from an actual completion input. It
/// has no timer of its own, so a cleanup that never completes at all stays
/// `pending` forever: absence of completion is not independently detectable
/// here and must be caught by the caller's own timer armed on
/// `cleanupDeadlineMonotonicNanoseconds`.
///
/// `completedOverBudget` means the completion instant was trusted and late.
/// `completedOutOfOrder` means the instant itself could not be trusted, so the
/// recorded time is a clamped bound rather than an observation.
public enum StageBLifecycleCleanupState: String, Equatable, Sendable {
  case notStarted
  case notRequired
  case pending
  case completedWithinBudget
  case completedOverBudget
  case completedOutOfOrder
}

/// The categories of side work a terminal transition must cancel.
public enum StageBLifecycleCancellationScope:
  String, Equatable, Sendable, CaseIterable
{
  case timers
  case sockets
  case nativeWork
}

/// One effect the caller must perform. The machine performs none of them.
public enum StageBLifecycleAction: Equatable, Sendable {
  case armDeadlineTimer(atMonotonicNanoseconds: UInt64)
  case cancel(StageBLifecycleCancellationScope)
  case stopEngineHandle(StageBLifecycleEngineHandle)
  case runCleanup(byMonotonicNanoseconds: UInt64)
}

/// An action bound to the exact generation that owns the affected resource.
///
/// The binding is what makes an orphaned resource actionable: a stop directed
/// at generation N is emitted while generation N+1 is live, and the caller can
/// tell the two apart without consulting the machine again.
public struct StageBLifecycleEffect: Equatable, Sendable {
  public let generation: StageBLifecycleGeneration
  public let action: StageBLifecycleAction

  public init(
    generation: StageBLifecycleGeneration,
    action: StageBLifecycleAction
  ) {
    self.generation = generation
    self.action = action
  }
}

/// What the machine did with one input.
///
/// `ignoredStaleGeneration` and `ignoredTerminal` may still carry effects: a
/// `wgTurnOn` that succeeds after its attempt was abandoned is ignored as a
/// transition and still yields a stop directive for the orphaned handle.
public enum StageBLifecycleDisposition: String, Equatable, Sendable {
  case accepted
  case ignoredStaleGeneration
  case ignoredTerminal
  case ignoredDuplicate
  case ignoredNotApplicable
  case rejected
}

/// The machine's complete answer to one input.
public struct StageBLifecycleDirective: Equatable, Sendable {
  public let disposition: StageBLifecycleDisposition
  public let state: StageBLifecycleState
  public let terminalReason: StageBLifecycleTerminalReason?
  public let effects: [StageBLifecycleEffect]

  public init(
    disposition: StageBLifecycleDisposition,
    state: StageBLifecycleState,
    terminalReason: StageBLifecycleTerminalReason?,
    effects: [StageBLifecycleEffect]
  ) {
    self.disposition = disposition
    self.state = state
    self.terminalReason = terminalReason
    self.effects = effects
  }
}

/// Immutable identity of one start attempt.
///
/// Equality requires both the attempt nonce and the sequence to match, so
/// neither a replayed nonce under a new sequence nor a foreign nonce reusing a
/// live sequence is accepted as the current generation.
public struct StageBLifecycleGeneration:
  Equatable, Hashable, Sendable
{
  public let attemptNonce: [UInt8]
  public let sequence: UInt64

  public init(attemptNonce: [UInt8], sequence: UInt64) throws {
    guard attemptNonce.count == 16,
      attemptNonce[6] & 0xf0 == 0x40,
      attemptNonce[8] & 0xc0 == 0x80
    else {
      throw StageBLifecycleError.invalidIdentifier
    }
    guard sequence > 0 else {
      throw StageBLifecycleError.invalidGeneration
    }
    self.attemptNonce = Array(attemptNonce)
    self.sequence = sequence
  }
}

/// The opaque `wgTurnOn` handle owned by one attempt.
///
/// The upstream engine returns a negative value on failure, so a negative
/// handle is never a startable resource. The raw value carries no generation
/// of its own: the operating system may hand the same `Int32` to a later
/// engine, which is precisely why the machine, not the caller, decides whether
/// a reported value may be stopped.
public struct StageBLifecycleEngineHandle:
  Equatable, Hashable, Sendable
{
  public let value: Int32

  public init(_ value: Int32) throws {
    guard value >= 0 else {
      throw StageBLifecycleError.invalidHandle
    }
    self.value = value
  }
}

/// Sanitized, allowlisted view of the machine's recorded state.
public struct StageBLifecycleSnapshot: Equatable, Sendable {
  public let schema: String
  public let state: StageBLifecycleState
  public let generation: StageBLifecycleGeneration?
  public let t0MonotonicNanoseconds: UInt64?
  public let deadlineMonotonicNanoseconds: UInt64?
  public let terminalReason: StageBLifecycleTerminalReason?
  public let terminalAtMonotonicNanoseconds: UInt64?
  public let cleanupState: StageBLifecycleCleanupState
  public let cleanupDeadlineMonotonicNanoseconds: UInt64?
  public let cleanupCompletedAtMonotonicNanoseconds: UInt64?
  public let engineHandleOwned: Bool
  /// Cleanup directives emitted for the current generation. It is 0 or 1.
  public let cleanupDirectivesEmitted: Int
  /// Orphaned-handle stops directed over this machine's whole lifetime, not
  /// per generation: the stops belong to generations that are already gone.
  public let staleEngineHandleStopsDirected: Int
  /// Stops the machine has directed and the caller has not yet confirmed.
  /// A new attempt cannot begin while this is nonzero.
  public let outstandingEngineHandleStops: Int
  /// Reports of a raw handle value the machine could not attribute to one
  /// engine. Every one of them fails the live attempt closed.
  public let aliasedEngineHandleReports: Int
  /// Handle reports refused because their generation fell out of the stop
  /// ledger. None of them produced a stop directive.
  public let unattributableStaleHandleReports: Int
  /// Generations at or below this sequence are no longer stoppable.
  public let stopLedgerHorizonSequence: UInt64

  fileprivate init(
    state: StageBLifecycleState,
    attempt: StageBLifecycleAttempt?,
    staleEngineHandleStopsDirected: Int,
    outstandingEngineHandleStops: Int,
    aliasedEngineHandleReports: Int,
    unattributableStaleHandleReports: Int,
    stopLedgerHorizonSequence: UInt64
  ) {
    schema = "winn-stageb-provider-lifecycle-snapshot/1"
    self.state = state
    generation = attempt?.generation
    t0MonotonicNanoseconds = attempt?.t0MonotonicNanoseconds
    deadlineMonotonicNanoseconds =
      attempt?.deadlineMonotonicNanoseconds
    terminalReason = attempt?.terminalReason
    terminalAtMonotonicNanoseconds =
      attempt?.terminalAtMonotonicNanoseconds
    cleanupState = attempt?.cleanupState ?? .notStarted
    cleanupDeadlineMonotonicNanoseconds =
      attempt?.cleanupDeadlineMonotonicNanoseconds
    cleanupCompletedAtMonotonicNanoseconds =
      attempt?.cleanupCompletedAtMonotonicNanoseconds
    engineHandleOwned = attempt?.handle != nil
    cleanupDirectivesEmitted =
      attempt?.cleanupDirectivesEmitted ?? 0
    self.staleEngineHandleStopsDirected =
      staleEngineHandleStopsDirected
    self.outstandingEngineHandleStops = outstandingEngineHandleStops
    self.aliasedEngineHandleReports = aliasedEngineHandleReports
    self.unattributableStaleHandleReports =
      unattributableStaleHandleReports
    self.stopLedgerHorizonSequence = stopLedgerHorizonSequence
  }
}

private final class StageBLifecycleAttempt {
  let generation: StageBLifecycleGeneration
  let t0MonotonicNanoseconds: UInt64
  let deadlineMonotonicNanoseconds: UInt64
  let admissibleCeilingMonotonicNanoseconds: UInt64
  var state: StageBLifecycleState = .starting
  var handle: StageBLifecycleEngineHandle?
  var terminalReason: StageBLifecycleTerminalReason?
  var terminalAtMonotonicNanoseconds: UInt64?
  var cleanupState: StageBLifecycleCleanupState = .notStarted
  var cleanupDeadlineMonotonicNanoseconds: UInt64?
  var cleanupCompletedAtMonotonicNanoseconds: UInt64?
  var cleanupDirectivesEmitted = 0

  init(
    generation: StageBLifecycleGeneration,
    t0MonotonicNanoseconds: UInt64,
    deadlineMonotonicNanoseconds: UInt64,
    admissibleCeilingMonotonicNanoseconds: UInt64
  ) {
    self.generation = generation
    self.t0MonotonicNanoseconds = t0MonotonicNanoseconds
    self.deadlineMonotonicNanoseconds = deadlineMonotonicNanoseconds
    self.admissibleCeilingMonotonicNanoseconds =
      admissibleCeilingMonotonicNanoseconds
  }
}

private struct StageBLifecycleStopKey: Hashable {
  let generation: StageBLifecycleGeneration
  let value: Int32
}

/// Pure, generation-bound Stage B provider lifecycle.
///
/// It imports no NetworkExtension API, owns no timer, opens no socket, and
/// performs no native call. Every input carries a generation identity and an
/// already-sampled monotonic instant; every output is a directive the caller
/// executes. The whole machine is therefore directly unit-testable.
///
/// Six invariants hold for every input:
///
/// 1. an input whose generation is not the current one cannot change any
///    recorded state, including the monotonic watermark;
/// 2. the first terminal transition records the authoritative outcome and no
///    later terminal input can overwrite it;
/// 3. the deadline is frozen at `T0 + StageBProtectedFlow.deadlineNanoseconds`
///    when the attempt begins, never recomputed from the instant of a later
///    check, so a slow path cannot extend its own budget;
/// 4. a non-success terminal emits its cleanup directive exactly once, with an
///    absolute completion deadline of terminal + 250 ms;
/// 5. success is recorded only for a `running` attempt that owns its engine
///    handle, and that handle is never stopped by any later callback; and
/// 6. a raw handle value is stopped only while the machine can attribute it to
///    exactly one engine. Ambiguity is never resolved by guessing.
public final class StageBProviderLifecycle: @unchecked Sendable {
  /// The frozen cleanup budget from the Stage B physical evidence contract.
  public static let cleanupBudgetNanoseconds: UInt64 = 250_000_000
  /// Hard bound on retained stop tombstones. The ledger evicts oldest-first
  /// and refuses to act on generations it has forgotten, so its memory is
  /// capped without ever silently permitting a second stop.
  public static let stopLedgerCapacity = 128

  private let lock = NSLock()
  private var attempt: StageBLifecycleAttempt?
  private var nextSequence: UInt64
  private var monotonicWatermark: UInt64 = 0
  private var staleStops = 0
  private var aliasedReports = 0
  /// Raw handle value to the generation whose stop directive is unconfirmed.
  /// Keying by value is deliberate: two engines cannot hold one value at once,
  /// so a second claimant on the same value is the ambiguity to refuse.
  private var outstandingStops = [Int32: StageBLifecycleGeneration]()
  /// Tombstones for every `(generation, rawValue)` pair already stop-directed,
  /// so no pair is ever directed twice.
  ///
  /// These deliberately survive `beginAttempt`. A confirmed stop's callback can
  /// still arrive again afterwards, and by then the operating system may have
  /// recycled that `Int32`; without the tombstone the repeat would direct a
  /// second stop against whatever holds the value now.
  private var directedStops = Set<StageBLifecycleStopKey>()
  /// Insertion order for `directedStops`, so the ledger evicts oldest-first and
  /// stays bounded by `stopLedgerCapacity`.
  private var directedStopOrder = [StageBLifecycleStopKey]()
  /// Generations at or below this sequence can no longer be proven un-stopped,
  /// because their tombstones were evicted. Their handle reports are refused
  /// rather than stopped on a guess.
  private var stopLedgerHorizonSequence: UInt64 = 0
  private var unattributableStaleReports = 0

  /// - Parameter nextGenerationSequence: the first sequence this machine will
  ///   mint. A provider recreated after a crash can resume above the sequence
  ///   it last used instead of reissuing one. Values below 1 are raised to 1;
  ///   the sequence space is finite and is checked, not assumed.
  public init(nextGenerationSequence: UInt64 = 1) {
    nextSequence = max(1, nextGenerationSequence)
  }

  public func snapshot() -> StageBLifecycleSnapshot {
    lock.lock()
    defer { lock.unlock() }
    return StageBLifecycleSnapshot(
      state: attempt?.state ?? .idle,
      attempt: attempt,
      staleEngineHandleStopsDirected: staleStops,
      outstandingEngineHandleStops: outstandingStops.count,
      aliasedEngineHandleReports: aliasedReports,
      unattributableStaleHandleReports: unattributableStaleReports,
      stopLedgerHorizonSequence: stopLedgerHorizonSequence
    )
  }

  /// Mints the next generation and freezes its absolute deadline.
  ///
  /// A new attempt is admissible only from `idle` or from a fully `cleaned`
  /// previous attempt with no unconfirmed stop directive outstanding, so at
  /// most one generation is ever live, the previous generation's cleanup is
  /// always accounted for, and no handle value is still ambiguous when a new
  /// engine is about to be started.
  public func beginAttempt(
    attemptNonce: [UInt8],
    t0MonotonicNanoseconds t0: UInt64,
    atMonotonicNanoseconds now: UInt64
  ) throws -> StageBLifecycleDirective {
    lock.lock()
    defer { lock.unlock() }

    if let previous = attempt {
      guard previous.state == .cleaned else {
        throw StageBLifecycleError.invalidState
      }
      guard t0 > previous.t0MonotonicNanoseconds else {
        throw StageBLifecycleError.invalidDeadline
      }
      guard attemptNonce != previous.generation.attemptNonce else {
        throw StageBLifecycleError.invalidIdentifier
      }
    }
    guard outstandingStops.isEmpty else {
      throw StageBLifecycleError.engineHandleStopOutstanding
    }
    // A first click cannot predate an instant the machine has already trusted
    // and recorded. Without this the new generation's whole budget would be
    // frozen from a T0 the machine has demonstrably seen past, and its
    // recorded chronology would contradict the previous attempt's own
    // observations. The watermark starts at zero, so a first attempt is
    // unconstrained; only a retry after recorded history is bound.
    guard t0 >= monotonicWatermark else {
      throw StageBLifecycleError.invalidDeadline
    }
    guard now >= monotonicWatermark, now >= t0 else {
      throw StageBLifecycleError.invalidDeadline
    }

    let (deadline, deadlineOverflow) = t0.addingReportingOverflow(
      StageBProtectedFlow.deadlineNanoseconds
    )
    // The widest instant this attempt will ever accept: the inclusive success
    // deadline, one cleanup budget for a stalled terminal wake, and one more
    // for the cleanup itself. The third budget is the headroom that keeps
    // `terminal + cleanupBudget` representable for any accepted instant.
    let (ceiling, ceilingOverflow) = deadline.addingReportingOverflow(
      Self.cleanupBudgetNanoseconds * 2
    )
    let (_, headroomOverflow) = ceiling.addingReportingOverflow(
      Self.cleanupBudgetNanoseconds
    )
    guard !deadlineOverflow, !ceilingOverflow, !headroomOverflow else {
      throw StageBLifecycleError.invalidDeadline
    }
    guard now <= deadline else {
      throw StageBLifecycleError.invalidDeadline
    }

    let generation = try StageBLifecycleGeneration(
      attemptNonce: attemptNonce,
      sequence: nextSequence
    )
    let (following, sequenceOverflow) =
      nextSequence.addingReportingOverflow(1)
    guard !sequenceOverflow else {
      throw StageBLifecycleError.generationSpaceExhausted
    }
    let started = StageBLifecycleAttempt(
      generation: generation,
      t0MonotonicNanoseconds: t0,
      deadlineMonotonicNanoseconds: deadline,
      admissibleCeilingMonotonicNanoseconds: ceiling
    )
    attempt = started
    nextSequence = following
    monotonicWatermark = now
    return StageBLifecycleDirective(
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
  }

  /// Records a completed `wgTurnOn`.
  ///
  /// A success that lands after its attempt was abandoned, superseded, or
  /// already terminal never becomes the machine's owned handle. It is returned
  /// as an explicit stop directive bound to the generation that started it, so
  /// the handle is stopped rather than leaked — unless the machine cannot tell
  /// which engine the raw value now names, in which case it stops nothing and
  /// fails the live attempt closed.
  public func recordStartSucceeded(
    generation: StageBLifecycleGeneration,
    handle: StageBLifecycleEngineHandle,
    atMonotonicNanoseconds now: UInt64
  ) -> StageBLifecycleDirective {
    lock.lock()
    defer { lock.unlock() }

    guard let current = attempt, current.generation == generation else {
      return resolveOrphanLocked(
        .ignoredStaleGeneration,
        generation: generation,
        handle: handle,
        now: now
      )
    }

    switch current.state {
    // An attempt object never carries `idle`. It is grouped with the states
    // that no longer expect a turn-on so the safest branch is taken if that
    // ever changes: resolve the report as an orphan, record no transition.
    case .idle, .terminal, .cleaned:
      return resolveOrphanLocked(
        .ignoredTerminal,
        generation: generation,
        handle: handle,
        now: now
      )
    case .running:
      guard current.handle != handle else {
        return directiveLocked(.ignoredDuplicate)
      }
      // A second distinct handle means a second engine inside one attempt.
      // Stop the newcomer and fail the attempt closed.
      let verdict = clockVerdictLocked(current, now: now)
      var effects = [StageBLifecycleEffect]()
      switch directStopLocked(
        generation: generation,
        handle: handle,
        countingAsStale: true
      ) {
      case let .direct(stop):
        effects.append(stop)
      case .alreadyDirected:
        break
      case .ambiguous:
        return aliasedTerminalLocked(current, at: verdict.instant)
      case .beyondLedgerHorizon:
        unattributableStaleReports += 1
      }
      effects += terminalEffectsLocked(
        current,
        reason: verdict.override ?? .engineChanged,
        at: verdict.instant
      )
      return directiveLocked(.rejected, effects: effects)
    case .starting:
      let verdict = clockVerdictLocked(current, now: now)
      guard verdict.override == nil else {
        // The turn-on outlived its own budget or arrived on an untrusted
        // clock. It is never adopted, and its handle is stopped.
        var effects = [StageBLifecycleEffect]()
        switch directStopLocked(
          generation: generation,
          handle: handle,
          countingAsStale: true
        ) {
        case let .direct(stop):
          effects.append(stop)
        case .alreadyDirected:
          break
        case .ambiguous:
          return aliasedTerminalLocked(current, at: verdict.instant)
        case .beyondLedgerHorizon:
          unattributableStaleReports += 1
        }
        effects += terminalEffectsLocked(
          current,
          reason: verdict.override!,
          at: verdict.instant
        )
        return directiveLocked(.rejected, effects: effects)
      }
      guard outstandingStops[handle.value] == nil else {
        // This exact raw value is already under an unconfirmed stop directive
        // for another engine. Adopting it now would make one `Int32` name two
        // engines, so the attempt fails closed instead.
        return aliasedTerminalLocked(current, at: verdict.instant)
      }
      monotonicWatermark = verdict.instant
      current.handle = handle
      current.state = .running
      return directiveLocked(.accepted)
    }
  }

  /// Confirms that the caller executed one directed `stopEngineHandle`.
  ///
  /// Until a stop is confirmed the machine treats its raw value as ambiguous:
  /// it will not adopt that value for a new engine and will not begin a new
  /// attempt. This is the only way the machine can know a recycled `Int32` is
  /// safe to reuse without asking the caller to distinguish two identical
  /// values itself.
  public func recordEngineHandleStopped(
    generation: StageBLifecycleGeneration,
    handle: StageBLifecycleEngineHandle
  ) -> StageBLifecycleDirective {
    lock.lock()
    defer { lock.unlock() }

    guard let owner = outstandingStops[handle.value] else {
      return directiveLocked(.ignoredDuplicate)
    }
    guard owner == generation else {
      return directiveLocked(.ignoredStaleGeneration)
    }
    outstandingStops.removeValue(forKey: handle.value)
    return directiveLocked(.accepted)
  }

  /// Records a failed `wgTurnOn` for the given generation.
  public func recordStartFailed(
    generation: StageBLifecycleGeneration,
    atMonotonicNanoseconds now: UInt64
  ) -> StageBLifecycleDirective {
    lock.lock()
    defer { lock.unlock() }

    guard let current = attempt, current.generation == generation else {
      return directiveLocked(.ignoredStaleGeneration)
    }
    switch current.state {
    case .idle, .terminal, .cleaned:
      return directiveLocked(.ignoredTerminal)
    case .starting:
      let verdict = clockVerdictLocked(current, now: now)
      let effects = terminalEffectsLocked(
        current,
        reason: verdict.override ?? .startFailed,
        at: verdict.instant
      )
      return directiveLocked(
        verdict.override == nil ? .accepted : .rejected,
        effects: effects
      )
    case .running:
      // Start cannot fail after it already succeeded for this generation.
      // Fail closed and tear the adopted handle down.
      let verdict = clockVerdictLocked(current, now: now)
      let effects = terminalEffectsLocked(
        current,
        reason: verdict.override ?? .startFailed,
        at: verdict.instant
      )
      return directiveLocked(.rejected, effects: effects)
    }
  }

  /// Records a terminal outcome. The first one wins.
  ///
  /// A terminal transition attempted after the absolute deadline is recorded
  /// as `deadlineExceeded` whatever reason was requested, so an expired
  /// attempt cannot be relabelled as a success or an ordinary stop. A success
  /// requested by an attempt that is not `running` with its own engine handle
  /// is recorded as `successWithoutRunningEngine` for the same reason.
  public func recordTerminal(
    generation: StageBLifecycleGeneration,
    reason: StageBLifecycleRequestedTerminalReason,
    atMonotonicNanoseconds now: UInt64
  ) -> StageBLifecycleDirective {
    lock.lock()
    defer { lock.unlock() }

    guard let current = attempt, current.generation == generation else {
      return directiveLocked(.ignoredStaleGeneration)
    }
    switch current.state {
    case .idle, .terminal, .cleaned:
      return directiveLocked(.ignoredTerminal)
    case .starting, .running:
      let verdict = clockVerdictLocked(current, now: now)
      var recorded = verdict.override ?? reason.recorded
      var accepted = verdict.override == nil
      if recorded == .succeeded,
        current.state != .running || current.handle == nil
      {
        recorded = .successWithoutRunningEngine
        accepted = false
      }
      let effects = terminalEffectsLocked(
        current,
        reason: recorded,
        at: verdict.instant
      )
      return directiveLocked(
        accepted ? .accepted : .rejected,
        effects: effects
      )
    }
  }

  /// Handles the caller's absolute-deadline timer wake.
  ///
  /// Exactly at the inclusive deadline the attempt stays live and the caller
  /// is told to rearm at deadline + 1, matching the coordinator, so a wake at
  /// exactly `T0 + 3s` cannot strand a live attempt.
  public func handleDeadlineTimerFired(
    generation: StageBLifecycleGeneration,
    atMonotonicNanoseconds now: UInt64
  ) -> StageBLifecycleDirective {
    lock.lock()
    defer { lock.unlock() }

    guard let current = attempt, current.generation == generation else {
      return directiveLocked(.ignoredStaleGeneration)
    }
    switch current.state {
    case .idle, .terminal, .cleaned:
      return directiveLocked(.ignoredTerminal)
    case .starting, .running:
      let verdict = clockVerdictLocked(current, now: now)
      guard let override = verdict.override else {
        monotonicWatermark = verdict.instant
        return directiveLocked(
          .accepted,
          effects: [
            StageBLifecycleEffect(
              generation: current.generation,
              action: .armDeadlineTimer(
                atMonotonicNanoseconds:
                  current.deadlineMonotonicNanoseconds + 1
              )
            )
          ]
        )
      }
      let effects = terminalEffectsLocked(
        current,
        reason: override,
        at: verdict.instant
      )
      // Expiry is exactly what this timer exists to detect, so it is an
      // accepted input; an untrusted clock reading is not.
      return directiveLocked(
        override == .deadlineExceeded ? .accepted : .rejected,
        effects: effects
      )
    }
  }

  /// Records that the directed cleanup finished. It is accepted exactly once.
  ///
  /// The completion instant is held to the same discipline as the attempt
  /// clock: a reading before the terminal decision, before the watermark, or
  /// beyond the attempt's frozen ceiling is never stored as an observation. It
  /// is clamped to the nearest trustworthy bound and recorded as
  /// `completedOutOfOrder`, so the stored timestamps stay truthful and ordered.
  public func recordCleanupCompleted(
    generation: StageBLifecycleGeneration,
    atMonotonicNanoseconds now: UInt64
  ) -> StageBLifecycleDirective {
    lock.lock()
    defer { lock.unlock() }

    guard let current = attempt, current.generation == generation else {
      return directiveLocked(.ignoredStaleGeneration)
    }
    guard current.state == .terminal else {
      // `cleaned` lands here too: the second completion changes nothing.
      return directiveLocked(
        current.state == .cleaned
          ? .ignoredDuplicate : .ignoredNotApplicable
      )
    }
    // The `pending` clause is a stated precondition, not an independent
    // check: the only other cleanup state a `terminal` attempt can hold is
    // `notRequired`, which carries no cleanup deadline and is already
    // excluded by the bind below. Mutating that clause alone changes no
    // reachable behaviour.
    guard current.cleanupState == .pending,
      let terminalAt = current.terminalAtMonotonicNanoseconds,
      let cleanupDeadline =
        current.cleanupDeadlineMonotonicNanoseconds
    else {
      return directiveLocked(.ignoredNotApplicable)
    }

    let floor = max(terminalAt, monotonicWatermark)
    let ceiling = current.admissibleCeilingMonotonicNanoseconds
    let recordedInstant: UInt64
    let recordedState: StageBLifecycleCleanupState
    let disposition: StageBLifecycleDisposition
    if now < floor {
      recordedInstant = floor
      recordedState = .completedOutOfOrder
      disposition = .rejected
    } else if now > ceiling {
      recordedInstant = ceiling
      recordedState = .completedOutOfOrder
      disposition = .rejected
    } else if now > cleanupDeadline {
      recordedInstant = now
      recordedState = .completedOverBudget
      disposition = .rejected
    } else {
      recordedInstant = now
      recordedState = .completedWithinBudget
      disposition = .accepted
      // Only an accepted completion moves the watermark. An out-of-order or
      // out-of-budget instant is recorded as a fact about cleanup without
      // becoming the floor that every later input must clear.
      monotonicWatermark = max(monotonicWatermark, now)
    }
    current.cleanupCompletedAtMonotonicNanoseconds = recordedInstant
    current.cleanupState = recordedState
    current.state = .cleaned
    return directiveLocked(disposition)
  }

  /// Decides what a reported handle means when no transition can accept it.
  private func resolveOrphanLocked(
    _ disposition: StageBLifecycleDisposition,
    generation: StageBLifecycleGeneration,
    handle: StageBLifecycleEngineHandle,
    now: UInt64
  ) -> StageBLifecycleDirective {
    if let current = attempt, let owned = current.handle,
      owned.value == handle.value
    {
      guard current.generation != generation else {
        // The handle a successful terminal deliberately retains. Stopping it
        // would tear down the live tunnel, so a repeat callback for the very
        // same handle is a duplicate and nothing else.
        return directiveLocked(.ignoredDuplicate)
      }
      let verdict = clockVerdictLocked(current, now: now)
      return aliasedTerminalLocked(current, at: verdict.instant)
    }
    switch directStopLocked(
      generation: generation,
      handle: handle,
      countingAsStale: true
    ) {
    case let .direct(stop):
      return directiveLocked(disposition, effects: [stop])
    case .alreadyDirected:
      return directiveLocked(.ignoredDuplicate)
    case .ambiguous:
      guard let current = attempt else {
        // An ambiguous value with no live attempt to fail closed. Nothing is
        // stopped; the report is counted and refused.
        aliasedReports += 1
        return directiveLocked(.rejected)
      }
      let verdict = clockVerdictLocked(current, now: now)
      return aliasedTerminalLocked(current, at: verdict.instant)
    case .beyondLedgerHorizon:
      // The live attempt is untouched: a forgotten generation contests
      // nothing about it, so refusing the stop is the whole remedy.
      return refuseUnattributableLocked()
    }
  }

  /// Whether one `(generation, handle)` pair may be stopped right now.
  private enum StageBLifecycleStopResolution {
    /// The pair is attributable and this is its first stop directive.
    case direct(StageBLifecycleEffect)
    /// This exact pair was already directed; a second stop would target a
    /// handle the caller may already have closed.
    case alreadyDirected
    /// The raw value is claimed by another generation, so no stop can name one
    /// engine unambiguously.
    case ambiguous
    /// The generation is older than the ledger can still account for, so the
    /// machine cannot prove this pair was not already stopped.
    case beyondLedgerHorizon
  }

  private func directStopLocked(
    generation: StageBLifecycleGeneration,
    handle: StageBLifecycleEngineHandle,
    countingAsStale: Bool
  ) -> StageBLifecycleStopResolution {
    let key = StageBLifecycleStopKey(
      generation: generation,
      value: handle.value
    )
    guard !directedStops.contains(key) else {
      return .alreadyDirected
    }
    guard generation.sequence > stopLedgerHorizonSequence else {
      return .beyondLedgerHorizon
    }
    if let owner = outstandingStops[handle.value], owner != generation {
      return .ambiguous
    }
    guard makeLedgerRoomLocked(for: generation) else {
      return .beyondLedgerHorizon
    }
    directedStops.insert(key)
    directedStopOrder.append(key)
    outstandingStops[handle.value] = generation
    if countingAsStale {
      staleStops += 1
    }
    return .direct(
      StageBLifecycleEffect(
        generation: generation,
        action: .stopEngineHandle(handle)
      )
    )
  }

  /// Frees one ledger slot when the tombstone set is full.
  ///
  /// Only a generation strictly older than the live one is ever evicted, so the
  /// horizon can never rise to the current generation and the attempt's own
  /// handle can never become unstoppable. If every slot belongs to the live
  /// generation the ledger refuses to grow instead of forgetting a stop.
  private func makeLedgerRoomLocked(
    for generation: StageBLifecycleGeneration
  ) -> Bool {
    guard directedStopOrder.count >= Self.stopLedgerCapacity else {
      return true
    }
    // The bar is the live attempt's own sequence and nothing else. Taking the
    // maximum with the incoming generation would let a report bearing a higher
    // sequence raise the bar past the live attempt, evict the live attempt's
    // own tombstone, and push the horizon up to it — which would make the
    // running engine's handle unstoppable.
    guard let liveSequence = attempt?.generation.sequence else {
      return false
    }
    guard
      let index = directedStopOrder.firstIndex(where: {
        $0.generation.sequence < liveSequence
      })
    else {
      return false
    }
    let evicted = directedStopOrder.remove(at: index)
    directedStops.remove(evicted)
    stopLedgerHorizonSequence = max(
      stopLedgerHorizonSequence,
      evicted.generation.sequence
    )
    return true
  }

  private func refuseUnattributableLocked() -> StageBLifecycleDirective {
    // Refusing can strand a handle whose generation is older than the ledger
    // window. That is the deliberate trade: a stop naming a value the machine
    // can no longer attribute is more dangerous than an unstopped handle from
    // an attempt this many generations old, because the value may now belong
    // to a live engine.
    unattributableStaleReports += 1
    return directiveLocked(.rejected)
  }

  private func aliasedTerminalLocked(
    _ current: StageBLifecycleAttempt,
    at instant: UInt64
  ) -> StageBLifecycleDirective {
    aliasedReports += 1
    guard current.state == .starting || current.state == .running else {
      // The live attempt is already terminal, so there is nothing left to
      // fail closed. The ambiguous value is counted and never stopped.
      return directiveLocked(.rejected)
    }
    let effects = terminalEffectsLocked(
      current,
      reason: .engineHandleAliased,
      at: instant
    )
    return directiveLocked(.rejected, effects: effects)
  }

  private func terminalEffectsLocked(
    _ current: StageBLifecycleAttempt,
    reason: StageBLifecycleTerminalReason,
    at instant: UInt64
  ) -> [StageBLifecycleEffect] {
    monotonicWatermark = instant
    current.state = .terminal
    current.terminalReason = reason
    current.terminalAtMonotonicNanoseconds = instant

    var effects: [StageBLifecycleEffect] = [
      .timers, .sockets, .nativeWork,
    ].map {
      StageBLifecycleEffect(
        generation: current.generation,
        action: .cancel($0)
      )
    }
    guard reason != .succeeded else {
      // Success keeps the engine handle: the tunnel stays up and there is
      // nothing to tear down.
      current.cleanupState = .notRequired
      return effects
    }
    if let handle = current.handle {
      switch directStopLocked(
        generation: current.generation,
        handle: handle,
        countingAsStale: false
      ) {
      case let .direct(stop):
        effects.append(stop)
      case .alreadyDirected:
        break
      case .ambiguous:
        // Adoption refuses any value that already carries an outstanding stop,
        // so the attempt's own handle cannot be claimed by another generation.
        // No accepted input reaches this branch; it counts the report instead
        // of dropping the stop silently.
        aliasedReports += 1
      case .beyondLedgerHorizon:
        // `makeLedgerRoomLocked` never evicts at or above the live sequence,
        // so the live attempt's own handle cannot fall past the horizon. This
        // counts rather than dropping the stop silently.
        unattributableStaleReports += 1
      }
      current.handle = nil
    }
    // `beginAttempt` proved ceiling + cleanupBudget is representable and
    // `clockVerdictLocked` clamps every instant to that ceiling, so the
    // reported overflow is not reachable from any accepted input; the checked
    // add is here only so an unchecked one can never trap.
    let (cleanupDeadline, overflow) = instant.addingReportingOverflow(
      Self.cleanupBudgetNanoseconds
    )
    current.cleanupDeadlineMonotonicNanoseconds =
      overflow ? UInt64.max : cleanupDeadline
    current.cleanupState = .pending
    current.cleanupDirectivesEmitted += 1
    effects.append(
      StageBLifecycleEffect(
        generation: current.generation,
        action: .runCleanup(
          byMonotonicNanoseconds:
            overflow ? UInt64.max : cleanupDeadline
        )
      )
    )
    return effects
  }

  /// Classifies one caller-supplied instant against this attempt's frozen
  /// bounds and returns the instant the machine is willing to record.
  ///
  /// A rolled-back reading is replaced by the last trusted watermark and an
  /// out-of-range reading by the attempt's frozen ceiling, because neither
  /// value can be recorded as an observation.
  private func clockVerdictLocked(
    _ current: StageBLifecycleAttempt,
    now: UInt64
  ) -> (instant: UInt64, override: StageBLifecycleTerminalReason?) {
    if now < monotonicWatermark {
      return (monotonicWatermark, .clockRollback)
    }
    if now > current.admissibleCeilingMonotonicNanoseconds {
      return (
        current.admissibleCeilingMonotonicNanoseconds,
        .clockOutOfRange
      )
    }
    if now > current.deadlineMonotonicNanoseconds {
      return (now, .deadlineExceeded)
    }
    return (now, nil)
  }

  private func directiveLocked(
    _ disposition: StageBLifecycleDisposition,
    effects: [StageBLifecycleEffect] = []
  ) -> StageBLifecycleDirective {
    StageBLifecycleDirective(
      disposition: disposition,
      state: attempt?.state ?? .idle,
      terminalReason: attempt?.terminalReason,
      effects: effects
    )
  }
}
