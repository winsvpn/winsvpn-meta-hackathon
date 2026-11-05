import Foundation

/// A bidirectional circuit's two shapers. Owned exclusively by its serial
/// `RotationBufferPool`/`StageAHarness`; it is not `Sendable`.
public final class CircuitBufferSet {
    public let inboundShaper: PrivacyShaper
    public let outboundShaper: PrivacyShaper
    public let allocatedCellBytes: Int

    public var inbound: FixedCellRing { inboundShaper.ring }
    public var outbound: FixedCellRing { outboundShaper.ring }

    public init(
        capacityPerDirection: Int,
        maximumShuffleNanoseconds: UInt64 =
            WCF3Constants.maximumShuffleNanoseconds
    ) throws {
        inboundShaper = try PrivacyShaper(
            capacity: capacityPerDirection,
            maximumShuffleNanoseconds: maximumShuffleNanoseconds
        )
        outboundShaper = try PrivacyShaper(
            capacity: capacityPerDirection,
            maximumShuffleNanoseconds: maximumShuffleNanoseconds
        )
        allocatedCellBytes =
            inboundShaper.ring.allocatedCellBytes +
            outboundShaper.ring.allocatedCellBytes
    }

    public func reset() {
        inbound.reset()
        outbound.reset()
    }
}

public enum RotationStartResult: Equatable, Sendable {
    case started(standbyIndex: Int, deadlineNanoseconds: UInt64)
    case alreadyOverlapping
}

/// Preallocates both circuit buffer sets. Rotation changes ownership only, so
/// make-before-break cannot create a third cell pool or an unbounded peak.
///
/// Owned exclusively by its serial `StageAHarness`; it is not `Sendable`. The
/// internal lock is retained as defensive synchronization for a possible later
/// producer/consumer split and is uncontended under the current serial owner.
public final class RotationBufferPool {
    public let maximumConcurrentCircuits =
        WCF3Constants.maximumConcurrentCircuits
    public let overlapLimitNanoseconds: UInt64
    public let allocatedCellBytes: Int

    private let lock = NSLock()
    private let circuits: [CircuitBufferSet]
    private var activeIndex = 0
    private var standbyIndex: Int?
    private var overlapDeadlineNanoseconds: UInt64?

    public init(
        capacityPerDirection: Int =
            WCF3Constants.defaultRingCapacity,
        maximumShuffleNanoseconds: UInt64 =
            WCF3Constants.maximumShuffleNanoseconds,
        overlapLimitNanoseconds: UInt64 =
            WCF3Constants.spikeRotationOverlapNanoseconds
    ) throws {
        self.overlapLimitNanoseconds = overlapLimitNanoseconds
        circuits = [
            try CircuitBufferSet(
                capacityPerDirection: capacityPerDirection,
                maximumShuffleNanoseconds: maximumShuffleNanoseconds
            ),
            try CircuitBufferSet(
                capacityPerDirection: capacityPerDirection,
                maximumShuffleNanoseconds: maximumShuffleNanoseconds
            ),
        ]
        allocatedCellBytes =
            circuits.reduce(0) { $0 + $1.allocatedCellBytes }
    }

    public func activeCircuit() -> CircuitBufferSet {
        withLock { circuits[activeIndex] }
    }

    public func standbyCircuit() -> CircuitBufferSet? {
        withLock {
            guard let standbyIndex else { return nil }
            return circuits[standbyIndex]
        }
    }

    public func beginRotation(
        nowNanoseconds: UInt64
    ) -> RotationStartResult {
        withLock {
            guard standbyIndex == nil else {
                return .alreadyOverlapping
            }
            let next = activeIndex == 0 ? 1 : 0
            circuits[next].reset()
            standbyIndex = next
            let deadline =
                nowNanoseconds.addingClamped(overlapLimitNanoseconds)
            overlapDeadlineNanoseconds = deadline
            return .started(
                standbyIndex: next,
                deadlineNanoseconds: deadline
            )
        }
    }

    @discardableResult
    public func completeRotation() -> Bool {
        withLock {
            guard let standbyIndex else { return false }
            let previous = activeIndex
            activeIndex = standbyIndex
            self.standbyIndex = nil
            overlapDeadlineNanoseconds = nil
            circuits[previous].reset()
            return true
        }
    }

    /// Cancels an in-flight make-before-break overlap without promoting the
    /// standby circuit. Stop paths use this to return to one active owner
    /// immediately and clear the standby buffers in place.
    @discardableResult
    public func cancelRotation() -> Bool {
        withLock {
            guard let standbyIndex else { return false }
            circuits[standbyIndex].reset()
            self.standbyIndex = nil
            overlapDeadlineNanoseconds = nil
            return true
        }
    }

    @discardableResult
    public func expireOverlapIfNeeded(
        nowNanoseconds: UInt64
    ) -> Bool {
        withLock {
            guard let standbyIndex,
                  let deadline = overlapDeadlineNanoseconds,
                  nowNanoseconds >= deadline
            else {
                return false
            }
            circuits[standbyIndex].reset()
            self.standbyIndex = nil
            overlapDeadlineNanoseconds = nil
            return true
        }
    }

    public func state() -> (
        activeIndex: Int,
        standbyIndex: Int?,
        deadlineNanoseconds: UInt64?
    ) {
        withLock {
            (
                activeIndex,
                standbyIndex,
                overlapDeadlineNanoseconds
            )
        }
    }

    public func allCircuits() -> [CircuitBufferSet] {
        circuits
    }

    private func withLock<T>(_ operation: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return operation()
    }
}

private extension UInt64 {
    func addingClamped(_ other: UInt64) -> UInt64 {
        let (value, overflow) = addingReportingOverflow(other)
        return overflow ? UInt64.max : value
    }
}
