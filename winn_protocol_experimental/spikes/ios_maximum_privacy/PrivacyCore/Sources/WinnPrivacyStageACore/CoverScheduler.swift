import Foundation

public enum CoverTrafficSemantics: String, Codable, Sendable {
    /// Conservative interpretation of the current plan: emit while the
    /// privacy circuit remains connected. A traffic-tail signal has no effect.
    case continuousWhileConnected

    /// Experimental interpretation that makes the 30-second tail meaningful:
    /// emit after traffic begins and stop 30 seconds after its most recent
    /// activity. This is not the normative protocol policy until explicitly
    /// selected in the specification.
    case activityWithThirtySecondTail
}

public struct CoverEmission: Equatable, Sendable {
    public let scheduledNanoseconds: UInt64
    public let observedNanoseconds: UInt64
    public let latenessNanoseconds: UInt64
    public let outboundCells: Int
    public let inboundCells: Int

    public init(
        scheduledNanoseconds: UInt64,
        observedNanoseconds: UInt64,
        outboundCells: Int = 1,
        inboundCells: Int = 1
    ) {
        self.scheduledNanoseconds = scheduledNanoseconds
        self.observedNanoseconds = observedNanoseconds
        latenessNanoseconds =
            observedNanoseconds >= scheduledNanoseconds
            ? observedNanoseconds - scheduledNanoseconds
            : 0
        self.outboundCells = outboundCells
        self.inboundCells = inboundCells
    }
}

/// Deterministic cover schedule. Polling late emits at most one pair and moves
/// the next deadline from `now`, deliberately preventing catch-up bursts.
public struct CoverScheduler: Sendable {
    public let semantics: CoverTrafficSemantics
    public let intervalNanoseconds: UInt64
    public let tailNanoseconds: UInt64

    public private(set) var isConnected = false
    public private(set) var nextDeadlineNanoseconds: UInt64?
    public private(set) var tailDeadlineNanoseconds: UInt64?

    public init(
        semantics: CoverTrafficSemantics,
        intervalNanoseconds: UInt64 =
            WCF3Constants.coverIntervalNanoseconds,
        tailNanoseconds: UInt64 =
            WCF3Constants.coverTailNanoseconds
    ) {
        precondition(
            intervalNanoseconds > 0,
            "cover interval must be positive"
        )
        self.semantics = semantics
        self.intervalNanoseconds = intervalNanoseconds
        self.tailNanoseconds = tailNanoseconds
    }

    public mutating func connect(nowNanoseconds: UInt64) {
        isConnected = true
        tailDeadlineNanoseconds = nil
        switch semantics {
        case .continuousWhileConnected:
            nextDeadlineNanoseconds =
                nowNanoseconds.addingClamped(intervalNanoseconds)
        case .activityWithThirtySecondTail:
            nextDeadlineNanoseconds = nil
        }
    }

    public mutating func noteUserTraffic(
        nowNanoseconds: UInt64
    ) {
        guard isConnected else { return }
        guard semantics == .activityWithThirtySecondTail else {
            return
        }
        tailDeadlineNanoseconds =
            nowNanoseconds.addingClamped(tailNanoseconds)
        if nextDeadlineNanoseconds == nil {
            nextDeadlineNanoseconds =
                nowNanoseconds.addingClamped(intervalNanoseconds)
        }
    }

    public mutating func poll(
        nowNanoseconds: UInt64
    ) -> CoverEmission? {
        guard isConnected,
              let scheduled = nextDeadlineNanoseconds,
              nowNanoseconds >= scheduled
        else {
            return nil
        }
        if semantics == .activityWithThirtySecondTail,
           let tailDeadlineNanoseconds,
           scheduled > tailDeadlineNanoseconds {
            nextDeadlineNanoseconds = nil
            return nil
        }
        let intervalsLate =
            (nowNanoseconds - scheduled) / intervalNanoseconds
        let intervalsToNext = intervalsLate.addingClamped(1)
        nextDeadlineNanoseconds = scheduled.addingClamped(
            intervalsToNext.multipliedClamped(
                by: intervalNanoseconds
            )
        )
        if semantics == .activityWithThirtySecondTail,
           let tailDeadlineNanoseconds,
           nextDeadlineNanoseconds! > tailDeadlineNanoseconds {
            nextDeadlineNanoseconds = nil
        }
        return CoverEmission(
            scheduledNanoseconds: scheduled,
            observedNanoseconds: nowNanoseconds
        )
    }

    public mutating func stop() {
        isConnected = false
        nextDeadlineNanoseconds = nil
        tailDeadlineNanoseconds = nil
    }
}

private extension UInt64 {
    func addingClamped(_ other: UInt64) -> UInt64 {
        let (value, overflow) = addingReportingOverflow(other)
        return overflow ? UInt64.max : value
    }

    func multipliedClamped(by other: UInt64) -> UInt64 {
        let (value, overflow) = multipliedReportingOverflow(by: other)
        return overflow ? UInt64.max : value
    }
}
