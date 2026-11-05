import Foundation

public struct PrivacyShaperSnapshot: Equatable, Sendable {
    public let ring: FixedCellRingSnapshot
    public let maximumShuffleNanoseconds: UInt64

    public init(
        ring: FixedCellRingSnapshot,
        maximumShuffleNanoseconds: UInt64
    ) {
        self.ring = ring
        self.maximumShuffleNanoseconds = maximumShuffleNanoseconds
    }
}

/// WCF3 fixed-cell encoder plus a bounded release-time shaper. It schedules a
/// cell within [now, now + 20 ms] and never creates a task or timer per cell.
///
/// Owned exclusively by its serial `StageAHarness`; it is not `Sendable`. Its
/// thread-safety derives entirely from the lock inside the wrapped ring.
public final class PrivacyShaper {
    public let ring: FixedCellRing
    public let maximumShuffleNanoseconds: UInt64

    public init(
        capacity: Int = WCF3Constants.defaultRingCapacity,
        maximumShuffleNanoseconds: UInt64 =
            WCF3Constants.maximumShuffleNanoseconds
    ) throws {
        guard maximumShuffleNanoseconds <=
                WCF3Constants.maximumShuffleNanoseconds
        else {
            throw PrivacyShaperError.shuffleWindowExceedsProtocolMaximum
        }
        ring = try FixedCellRing(capacity: capacity)
        self.maximumShuffleNanoseconds = maximumShuffleNanoseconds
    }

    @discardableResult
    public func enqueue(
        header: WCF3FrameHeader,
        payload: UnsafeRawBufferPointer,
        nowNanoseconds: UInt64,
        scheduleWord: UInt64,
        paddingFiller: WCF3Codec.PaddingFiller
    ) throws -> Bool {
        let divisor = maximumShuffleNanoseconds &+ 1
        let jitter = divisor == 0 ? 0 : scheduleWord % divisor
        let deadline = nowNanoseconds.addingClamped(jitter)
        return try ring.enqueue(
            enqueuedAtNanoseconds: nowNanoseconds,
            releaseDeadlineNanoseconds: deadline,
            sequence: header.sequence,
            isCover: header.kind == .cover
        ) { destination in
            try WCF3Codec.encode(
                header: header,
                payload: payload,
                totalSize: WCF3Constants.privacyCellSize,
                into: destination,
                paddingFiller: paddingFiller
            )
        }
    }

    public func dequeueEligible(
        nowNanoseconds: UInt64,
        selectionWord: UInt64,
        into destination: UnsafeMutableRawBufferPointer
    ) throws -> FixedCellMetadata? {
        try ring.dequeueEligible(
            nowNanoseconds: nowNanoseconds,
            selectionWord: selectionWord,
            into: destination
        )
    }

    public func snapshot() -> PrivacyShaperSnapshot {
        PrivacyShaperSnapshot(
            ring: ring.snapshot(),
            maximumShuffleNanoseconds: maximumShuffleNanoseconds
        )
    }
}

public enum PrivacyShaperError: Error, Equatable {
    case shuffleWindowExceedsProtocolMaximum
}

private extension UInt64 {
    func addingClamped(_ other: UInt64) -> UInt64 {
        let (value, overflow) = addingReportingOverflow(other)
        return overflow ? UInt64.max : value
    }
}
