import Foundation

public struct FixedCellMetadata: Equatable, Sendable {
    public let slot: Int
    public let enqueuedAtNanoseconds: UInt64
    public let releaseDeadlineNanoseconds: UInt64
    public let sequence: UInt64
    public let isCover: Bool

    public init(
        slot: Int,
        enqueuedAtNanoseconds: UInt64,
        releaseDeadlineNanoseconds: UInt64,
        sequence: UInt64,
        isCover: Bool
    ) {
        self.slot = slot
        self.enqueuedAtNanoseconds = enqueuedAtNanoseconds
        self.releaseDeadlineNanoseconds = releaseDeadlineNanoseconds
        self.sequence = sequence
        self.isCover = isCover
    }
}

public struct FixedCellRingSnapshot: Equatable, Sendable {
    public let capacity: Int
    public let occupied: Int
    public let occupiedCover: Int
    public let highWatermark: Int
    public let accepted: UInt64
    public let rejectedFull: UInt64
    public let emitted: UInt64
    public let retiredData: UInt64
    public let retiredCover: UInt64

    public init(
        capacity: Int,
        occupied: Int,
        occupiedCover: Int,
        highWatermark: Int,
        accepted: UInt64,
        rejectedFull: UInt64,
        emitted: UInt64,
        retiredData: UInt64,
        retiredCover: UInt64
    ) {
        self.capacity = capacity
        self.occupied = occupied
        self.occupiedCover = occupiedCover
        self.highWatermark = highWatermark
        self.accepted = accepted
        self.rejectedFull = rejectedFull
        self.emitted = emitted
        self.retiredData = retiredData
        self.retiredCover = retiredCover
    }
}

public enum FixedCellRingError: Error, Equatable {
    case invalidCapacity
    case invalidCellSize
    case encoderReturnedWrongSize
    case destinationTooSmall
}

/// A fixed-capacity cell store. The backing bytes and metadata arrays are
/// allocated exactly once. Selection scans from a randomized offset so due
/// cells can leave in a different order without allocating a shuffle list.
///
/// The store is owned exclusively by its serial `StageAHarness` and is not
/// `Sendable`. The internal lock is retained as defensive synchronization so
/// the same store stays correct if a later stage splits producer and consumer
/// onto separate executors.
public final class FixedCellRing {
    public typealias CellEncoder =
        (UnsafeMutableRawBufferPointer) throws -> Int

    public let capacity: Int
    public let cellSize: Int
    public let allocatedCellBytes: Int

    private let lock = NSLock()
    private let storage: UnsafeMutableRawBufferPointer
    private var occupied: [Bool]
    private var enqueuedAt: [UInt64]
    private var deadlines: [UInt64]
    private var sequences: [UInt64]
    private var coverFlags: [Bool]
    private var insertionCursor = 0
    private var occupiedCount = 0
    private var occupiedCoverCount = 0
    private var highWatermark = 0
    private var accepted: UInt64 = 0
    private var rejectedFull: UInt64 = 0
    private var emitted: UInt64 = 0
    private var retiredData: UInt64 = 0
    private var retiredCover: UInt64 = 0

    public init(
        capacity: Int = WCF3Constants.defaultRingCapacity,
        cellSize: Int = WCF3Constants.privacyCellSize
    ) throws {
        guard capacity > 0 else {
            throw FixedCellRingError.invalidCapacity
        }
        guard cellSize == WCF3Constants.privacyCellSize else {
            throw FixedCellRingError.invalidCellSize
        }
        self.capacity = capacity
        self.cellSize = cellSize
        allocatedCellBytes = capacity * cellSize
        storage = UnsafeMutableRawBufferPointer.allocate(
            byteCount: allocatedCellBytes,
            alignment: 64
        )
        storage.initializeMemory(as: UInt8.self, repeating: 0)
        occupied = [Bool](repeating: false, count: capacity)
        enqueuedAt = [UInt64](repeating: 0, count: capacity)
        deadlines = [UInt64](repeating: 0, count: capacity)
        sequences = [UInt64](repeating: 0, count: capacity)
        coverFlags = [Bool](repeating: false, count: capacity)
    }

    deinit {
        storage.initializeMemory(as: UInt8.self, repeating: 0)
        storage.deallocate()
    }

    @discardableResult
    public func enqueue(
        enqueuedAtNanoseconds: UInt64,
        releaseDeadlineNanoseconds: UInt64,
        sequence: UInt64,
        isCover: Bool,
        encoder: CellEncoder
    ) throws -> Bool {
        try withLock {
            guard occupiedCount < capacity else {
                rejectedFull &+= 1
                return false
            }
            guard let slot = firstFreeSlot() else {
                rejectedFull &+= 1
                return false
            }
            let destination = cellBuffer(slot: slot)
            let encodedSize: Int
            do {
                encodedSize = try encoder(destination)
            } catch {
                destination.initializeMemory(as: UInt8.self, repeating: 0)
                throw error
            }
            guard encodedSize == cellSize else {
                destination.initializeMemory(as: UInt8.self, repeating: 0)
                throw FixedCellRingError.encoderReturnedWrongSize
            }
            occupied[slot] = true
            enqueuedAt[slot] = enqueuedAtNanoseconds
            deadlines[slot] = releaseDeadlineNanoseconds
            sequences[slot] = sequence
            coverFlags[slot] = isCover
            occupiedCount += 1
            if isCover {
                occupiedCoverCount += 1
            }
            highWatermark = max(highWatermark, occupiedCount)
            accepted &+= 1
            insertionCursor = (slot + 1) % capacity
            return true
        }
    }

    /// Removes one due cell, starting the scan at a deterministic random
    /// offset. At most one cell is returned per call; callers own batching.
    public func dequeueEligible(
        nowNanoseconds: UInt64,
        selectionWord: UInt64,
        into destination: UnsafeMutableRawBufferPointer
    ) throws -> FixedCellMetadata? {
        try withLock {
            guard destination.count >= cellSize else {
                throw FixedCellRingError.destinationTooSmall
            }
            let start = Int(selectionWord % UInt64(capacity))
            for distance in 0 ..< capacity {
                let slot = (start + distance) % capacity
                guard occupied[slot],
                      deadlines[slot] <= nowNanoseconds
                else {
                    continue
                }
                let source = UnsafeRawBufferPointer(cellBuffer(slot: slot))
                UnsafeMutableRawBufferPointer(
                    rebasing: destination[0 ..< cellSize]
                ).copyBytes(from: source)
                let metadata = FixedCellMetadata(
                    slot: slot,
                    enqueuedAtNanoseconds: enqueuedAt[slot],
                    releaseDeadlineNanoseconds: deadlines[slot],
                    sequence: sequences[slot],
                    isCover: coverFlags[slot]
                )
                cellBuffer(slot: slot)
                    .initializeMemory(as: UInt8.self, repeating: 0)
                occupied[slot] = false
                if coverFlags[slot] {
                    occupiedCoverCount -= 1
                }
                enqueuedAt[slot] = 0
                deadlines[slot] = 0
                sequences[slot] = 0
                coverFlags[slot] = false
                occupiedCount -= 1
                emitted &+= 1
                return metadata
            }
            return nil
        }
    }

    public func reset() {
        withLock {
            storage.initializeMemory(as: UInt8.self, repeating: 0)
            for slot in 0 ..< capacity {
                if occupied[slot] {
                    if coverFlags[slot] {
                        retiredCover &+= 1
                    } else {
                        retiredData &+= 1
                    }
                }
                occupied[slot] = false
                enqueuedAt[slot] = 0
                deadlines[slot] = 0
                sequences[slot] = 0
                coverFlags[slot] = false
            }
            insertionCursor = 0
            occupiedCount = 0
            occupiedCoverCount = 0
        }
    }

    public func snapshot() -> FixedCellRingSnapshot {
        withLock {
            FixedCellRingSnapshot(
                capacity: capacity,
                occupied: occupiedCount,
                occupiedCover: occupiedCoverCount,
                highWatermark: highWatermark,
                accepted: accepted,
                rejectedFull: rejectedFull,
                emitted: emitted,
                retiredData: retiredData,
                retiredCover: retiredCover
            )
        }
    }

    private func firstFreeSlot() -> Int? {
        for distance in 0 ..< capacity {
            let slot = (insertionCursor + distance) % capacity
            if !occupied[slot] {
                return slot
            }
        }
        return nil
    }

    private func cellBuffer(
        slot: Int
    ) -> UnsafeMutableRawBufferPointer {
        let start = slot * cellSize
        return UnsafeMutableRawBufferPointer(
            rebasing: storage[start ..< start + cellSize]
        )
    }

    private func withLock<T>(
        _ operation: () throws -> T
    ) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try operation()
    }
}
