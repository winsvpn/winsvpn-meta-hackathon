import Foundation

public enum StageARotationCadence: String, Codable, Sendable {
    case protocolFifteenMinutes = "protocol-15m"
    case acceleratedAllocation = "accelerated-allocation"

    public var intervalNanoseconds: UInt64 {
        switch self {
        case .protocolFifteenMinutes:
            return WCF3Constants.circuitRotationNanoseconds
        case .acceleratedAllocation:
            return 100_000_000
        }
    }

    public var overlapNanoseconds: UInt64 {
        switch self {
        case .protocolFifteenMinutes:
            return WCF3Constants.spikeRotationOverlapNanoseconds
        case .acceleratedAllocation:
            return 50_000_000
        }
    }
}

public enum StageATestCondition: String, Codable, Sendable {
    case foregroundWiFi = "foreground-wifi"
    case lockedWiFi = "locked-wifi"
    case unpluggedCellular = "unplugged-cellular"
    case lowPowerMode = "low-power-mode"
    case acceleratedAllocation = "accelerated-allocation"
    case eightHourLocked = "eight-hour-locked"
    case stopLatency = "stop-latency"
    case smoke
}

public struct StageAConfiguration: Equatable, Sendable {
    public let mode: SpikeMode
    public let trafficProfile: SyntheticTrafficProfile
    public let coverSemantics: CoverTrafficSemantics
    public let rotationCadence: StageARotationCadence
    public let testCondition: StageATestCondition
    public let pairID: String
    public let durationNanoseconds: UInt64
    public let trafficActiveNanoseconds: UInt64

    public init(
        mode: SpikeMode,
        trafficProfile: SyntheticTrafficProfile,
        coverSemantics: CoverTrafficSemantics,
        rotationCadence: StageARotationCadence,
        testCondition: StageATestCondition = .foregroundWiFi,
        pairID: String =
            "01234567-89ab-cdef-0123-456789abcdef",
        durationNanoseconds: UInt64
    ) throws {
        guard durationNanoseconds >= 30_000_000_000,
              durationNanoseconds <= 28_800_000_000_000
        else {
            throw StageAHarnessError.invalidDuration
        }
        guard Self.validPairID(pairID) else {
            throw StageAHarnessError.invalidPairID
        }
        self.mode = mode
        self.trafficProfile = trafficProfile
        self.coverSemantics = coverSemantics
        self.rotationCadence = rotationCadence
        self.testCondition = testCondition
        self.pairID = pairID
        self.durationNanoseconds = durationNanoseconds
        trafficActiveNanoseconds =
            coverSemantics == .activityWithThirtySecondTail
            ? durationNanoseconds - WCF3Constants.coverTailNanoseconds
            : durationNanoseconds
    }

    private static func validPairID(_ value: String) -> Bool {
        guard value.count == 36 else { return false }
        for (index, character) in value.utf8.enumerated() {
            switch index {
            case 8, 13, 18, 23:
                guard character == 45 else { return false }
            default:
                guard (character >= 48 && character <= 57) ||
                        (character >= 97 && character <= 102)
                else {
                    return false
                }
            }
        }
        return true
    }
}

public struct StageAHarnessSnapshot: Equatable, Sendable {
    public let elapsedNanoseconds: UInt64
    public let completed: Bool
    public let dataPath: SpikeDataPathSnapshot

    public init(
        elapsedNanoseconds: UInt64,
        completed: Bool,
        dataPath: SpikeDataPathSnapshot
    ) {
        self.elapsedNanoseconds = elapsedNanoseconds
        self.completed = completed
        self.dataPath = dataPath
    }
}

public enum StageAHarnessError: Error, Equatable {
    case invalidDuration
    case invalidPairID
    case nonMonotonicTime
    case invalidConnectionContext
}

/// A Stage A resource harness. It produces and consumes only synthetic WCF3
/// cells in the extension process. It has no socket, packet-flow, or forwarding
/// API and therefore cannot carry device traffic.
///
/// This mutable type is intentionally not `Sendable`. Its owner must serialize
/// every call on one executor. The Packet Tunnel provider owns it exclusively
/// from its dedicated Stage A dispatch queue.
public final class StageAHarness {
    private static let nanosecondsPerSecond: UInt64 = 1_000_000_000
    private static let maximumAccountedStepNanoseconds: UInt64 = 100_000_000

    public let configuration: StageAConfiguration
    public let privacyPool: RotationBufferPool?

    private let context: WCF3ConnectionContext
    private var cover: CoverScheduler
    private var startNanoseconds: UInt64?
    private var lastStepNanoseconds: UInt64?
    private var nextRotationNanoseconds: UInt64?
    private var overlapCompletionNanoseconds: UInt64?
    private var overlapStartedNanoseconds: UInt64?
    private var maximumRotationOverlapNanoseconds: UInt64 = 0
    private var outboundProductionRemainder: UInt64 = 0
    private var inboundProductionRemainder: UInt64 = 0
    private var commonPathRemainder: UInt64 = 0
    private var commonPathUnits: UInt64 = 0
    private var commonPathActiveNanoseconds: UInt64 = 0
    private var commonPathAccumulator: UInt64 =
        0xbb67ae8584caa73b
    private var outboundDrainRemainder: UInt64 = 0
    private var inboundDrainRemainder: UInt64 = 0
    private var outboundDrainCredits = 0
    private var inboundDrainCredits = 0
    private var outboundSequence: UInt64 = 1
    private var inboundSequence: UInt64 = 1
    private var randomState: UInt64 = 0x6a09e667f3bcc909
    private var coverPairsAccepted: UInt64 = 0
    private var coverInboundCellsAccepted: UInt64 = 0
    private var coverOutboundCellsAccepted: UInt64 = 0
    private var coverInboundCellsEmitted: UInt64 = 0
    private var coverOutboundCellsEmitted: UInt64 = 0
    private var coverDeadlinesMissed: UInt64 = 0
    private var maximumCoverLatenessNanoseconds: UInt64 = 0
    private var maximumObservedQueueDelayNanoseconds: UInt64 = 0
    private var unaccountedWorkNanoseconds: UInt64 = 0
    private var backpressureEvents: UInt64 = 0
    private var backpressuredCells: UInt64 = 0
    private var occupancySamples: UInt64 = 0
    private var inboundOccupancyHistogram = [UInt64](
        repeating: 0,
        count: WCF3Constants.defaultRingCapacity + 1
    )
    private var outboundOccupancyHistogram = [UInt64](
        repeating: 0,
        count: WCF3Constants.defaultRingCapacity + 1
    )
    private var queueDelayHistogram = BoundedDelayHistogram()
    private var rotationCount: UInt64 = 0
    private var completionLatched = false
    private var outboundScratch = [UInt8](
        repeating: 0,
        count: WCF3Constants.privacyCellSize
    )
    private var inboundScratch = [UInt8](
        repeating: 0,
        count: WCF3Constants.privacyCellSize
    )
    private let syntheticPayload = [UInt8](
        repeating: 0x57,
        count: 64
    )

    public init(configuration: StageAConfiguration) throws {
        self.configuration = configuration
        if configuration.mode == .maximumPrivacy {
            privacyPool = try RotationBufferPool(
                maximumShuffleNanoseconds:
                    WCF3Constants.maximumShuffleNanoseconds,
                overlapLimitNanoseconds:
                    configuration.rotationCadence.overlapNanoseconds
            )
        } else {
            // This is an instrumentation-only common-path baseline. It owns
            // no fixed-cell buffers, cover scheduler workload, or rotations,
            // so evidence exposes the privacy path's incremental allocation.
            privacyPool = nil
        }
        cover = CoverScheduler(semantics: configuration.coverSemantics)
        do {
            context = try WCF3ConnectionContext(
                sessionID: Array(1 ... 16),
                bindingID: Array(17 ... 32),
                pskGeneration: 1,
                sequenceEpoch: 1
            )
        } catch {
            throw StageAHarnessError.invalidConnectionContext
        }
    }

    public func start(nowNanoseconds: UInt64) {
        guard startNanoseconds == nil else { return }
        startNanoseconds = nowNanoseconds
        lastStepNanoseconds = nowNanoseconds
        nextRotationNanoseconds = nowNanoseconds.addingClamped(
            configuration.rotationCadence.intervalNanoseconds
        )
        cover.connect(nowNanoseconds: nowNanoseconds)
        if configuration.mode == .maximumPrivacy,
           configuration.coverSemantics == .activityWithThirtySecondTail,
           configuration.trafficProfile != .idle {
            // Seed the activity interval at its exact logical start. This
            // makes a D-second active interval deterministically schedule D
            // one-hertz cover pairs, independent of the first timer jitter.
            cover.noteUserTraffic(nowNanoseconds: nowNanoseconds)
        }
    }

    public func step(
        nowNanoseconds: UInt64
    ) throws -> StageAHarnessSnapshot {
        if startNanoseconds == nil {
            start(nowNanoseconds: nowNanoseconds)
        }
        guard let startNanoseconds, let previous = lastStepNanoseconds,
              nowNanoseconds >= previous,
              previous >= startNanoseconds
        else {
            throw StageAHarnessError.nonMonotonicTime
        }
        if completionLatched {
            lastStepNanoseconds = nowNanoseconds
            return snapshot(nowNanoseconds: nowNanoseconds)
        }
        let observedElapsed = nowNanoseconds - startNanoseconds
        let workEnd = min(
            observedElapsed,
            configuration.durationNanoseconds
        )
        let previousEnd = min(
            previous - startNanoseconds,
            configuration.durationNanoseconds
        )
        let stepElapsed = workEnd - previousEnd
        let accounted = min(
            stepElapsed,
            Self.maximumAccountedStepNanoseconds
        )
        let previousActiveEnd = min(
            previousEnd,
            configuration.trafficActiveNanoseconds
        )
        let activeEnd = min(
            workEnd,
            configuration.trafficActiveNanoseconds
        )
        let activeElapsed = activeEnd - previousActiveEnd
        let activeAccounted = min(
            activeElapsed,
            Self.maximumAccountedStepNanoseconds
        )
        if configuration.trafficProfile.producerCellsPerSecond > 0 {
            unaccountedWorkNanoseconds &+=
                activeElapsed - activeAccounted
        }
        lastStepNanoseconds = nowNanoseconds
        let logicalNow = startNanoseconds.addingClamped(workEnd)

        if activeAccounted > 0 {
            runCommonPath(elapsedNanoseconds: activeAccounted)
            if configuration.mode == .maximumPrivacy,
               configuration.coverSemantics ==
                .activityWithThirtySecondTail {
                cover.noteUserTraffic(
                    nowNanoseconds:
                        startNanoseconds.addingClamped(activeEnd)
                )
            }
        }
        if configuration.mode == .maximumPrivacy {
            updateRotation(
                nowNanoseconds: logicalNow,
                allowStart:
                    observedElapsed < configuration.durationNanoseconds
            )
            try drainSyntheticCells(
                elapsedNanoseconds: accounted,
                nowNanoseconds: logicalNow
            )
            try emitCoverIfDue(
                scheduleNanoseconds: logicalNow,
                observedNanoseconds: nowNanoseconds
            )
            try produceSyntheticCells(
                elapsedNanoseconds: activeAccounted,
                nowNanoseconds: logicalNow
            )
            recordOccupancy()
        }
        if observedElapsed >= configuration.durationNanoseconds {
            finalize()
        }
        return snapshot(nowNanoseconds: nowNanoseconds)
    }

    /// Gives the provider a deadline-driven polling cadence. Busy synthetic
    /// profiles retain the 10 ms batching tick. Idle continuous cover sleeps
    /// until the next one-second cover deadline, then uses one 20 ms drain
    /// wakeup; Core and inactive activity-tail runs sample only once/second.
    public func recommendedNextStepDelayNanoseconds(
        nowNanoseconds: UInt64
    ) -> UInt64 {
        if completionLatched {
            return Self.nanosecondsPerSecond
        }
        if configuration.mode == .coreBaseline {
            return configuration.trafficProfile != .idle &&
                userTrafficIsActive(nowNanoseconds: nowNanoseconds)
                ? 10_000_000
                : Self.nanosecondsPerSecond
        }
        if configuration.rotationCadence == .acceleratedAllocation {
            return 10_000_000
        }
        if configuration.trafficProfile != .idle &&
            userTrafficIsActive(nowNanoseconds: nowNanoseconds) {
            return 10_000_000
        }
        let occupied = privacyPool?.allCircuits().contains {
            $0.inbound.snapshot().occupied > 0 ||
                $0.outbound.snapshot().occupied > 0
        } ?? false
        if occupied {
            return WCF3Constants.maximumShuffleNanoseconds
        }
        guard let deadline = cover.nextDeadlineNanoseconds else {
            return Self.nanosecondsPerSecond
        }
        if deadline <= nowNanoseconds {
            return 1_000_000
        }
        return min(
            deadline - nowNanoseconds,
            Self.nanosecondsPerSecond
        )
    }

    public func stop(nowNanoseconds: UInt64) -> StageAHarnessSnapshot {
        finalize()
        return snapshot(nowNanoseconds: nowNanoseconds)
    }

    public func snapshot(
        nowNanoseconds: UInt64
    ) -> StageAHarnessSnapshot {
        let circuits = privacyPool?.allCircuits() ?? []
        let ringSnapshots = circuits.flatMap {
            [$0.inbound.snapshot(), $0.outbound.snapshot()]
        }
        let inbound = circuits.map {
            $0.inbound.snapshot()
        }
        let outbound = circuits.map {
            $0.outbound.snapshot()
        }
        let totalAccepted = ringSnapshots.reduce(UInt64(0)) {
            $0 &+ $1.accepted
        }
        let totalEmitted = ringSnapshots.reduce(UInt64(0)) {
            $0 &+ $1.emitted
        }
        let totalDropped = ringSnapshots.reduce(UInt64(0)) {
            $0 &+ $1.rejectedFull
        }
        let totalRetiredData = ringSnapshots.reduce(UInt64(0)) {
            $0 &+ $1.retiredData
        }
        let totalRetiredCover = ringSnapshots.reduce(UInt64(0)) {
            $0 &+ $1.retiredCover
        }
        let inboundPendingCover = inbound.reduce(0) {
            $0 + $1.occupiedCover
        }
        let outboundPendingCover = outbound.reduce(0) {
            $0 + $1.occupiedCover
        }
        let inboundRetiredCover = inbound.reduce(UInt64(0)) {
            $0 &+ $1.retiredCover
        }
        let outboundRetiredCover = outbound.reduce(UInt64(0)) {
            $0 &+ $1.retiredCover
        }
        let rotationState = privacyPool?.state()
        let dataPath = SpikeDataPathSnapshot(
            allocatedPrivacyCellBytes:
                privacyPool?.allocatedCellBytes ?? 0,
            inboundQueueDepth: inbound.reduce(0) { $0 + $1.occupied },
            outboundQueueDepth:
                outbound.reduce(0) { $0 + $1.occupied },
            inboundHighWatermark:
                inbound.map(\.highWatermark).max() ?? 0,
            outboundHighWatermark:
                outbound.map(\.highWatermark).max() ?? 0,
            occupancySamples: occupancySamples,
            inboundOccupancyP99Cells:
                quantile99(inboundOccupancyHistogram),
            outboundOccupancyP99Cells:
                quantile99(outboundOccupancyHistogram),
            acceptedCells: totalAccepted,
            emittedCells: totalEmitted,
            droppedCells: totalDropped,
            retiredDataCells: totalRetiredData,
            retiredCoverCells: totalRetiredCover,
            commonPathUnits: commonPathUnits,
            commonPathActiveNanoseconds:
                commonPathActiveNanoseconds,
            commonPathChecksum: commonPathAccumulator,
            coverPairsAccepted: coverPairsAccepted,
            coverInboundCellsAccepted:
                coverInboundCellsAccepted,
            coverOutboundCellsAccepted:
                coverOutboundCellsAccepted,
            coverPairsEmitted: min(
                coverInboundCellsEmitted,
                coverOutboundCellsEmitted
            ),
            coverInboundCellsEmitted:
                coverInboundCellsEmitted,
            coverOutboundCellsEmitted:
                coverOutboundCellsEmitted,
            coverInboundCellsPending:
                inboundPendingCover,
            coverOutboundCellsPending:
                outboundPendingCover,
            coverInboundCellsRetired:
                inboundRetiredCover,
            coverOutboundCellsRetired:
                outboundRetiredCover,
            coverDeadlinesMissed: coverDeadlinesMissed,
            maximumCoverLatenessNanoseconds:
                maximumCoverLatenessNanoseconds,
            queueDelaySamples: queueDelayHistogram.sampleCount,
            queueDelayP99UpperBoundNanoseconds:
                queueDelayHistogram.quantile99UpperBound,
            queueDelayOver25Milliseconds:
                queueDelayHistogram.over25Milliseconds,
            maximumObservedQueueDelayNanoseconds:
                maximumObservedQueueDelayNanoseconds,
            unaccountedWorkNanoseconds:
                unaccountedWorkNanoseconds,
            backpressureEvents: backpressureEvents,
            backpressuredCells: backpressuredCells,
            rotationCount: rotationCount,
            maximumRotationOverlapNanoseconds:
                maximumRotationOverlapNanoseconds,
            rotationActiveCircuit: rotationState?.activeIndex,
            rotationStandbyCircuit: rotationState?.standbyIndex,
            rotationOverlapDeadlineNanoseconds:
                rotationState?.deadlineNanoseconds
        )
        return StageAHarnessSnapshot(
            elapsedNanoseconds: startNanoseconds.map {
                nowNanoseconds >= $0 ? nowNanoseconds - $0 : 0
            } ?? 0,
            completed: completionLatched,
            dataPath: dataPath
        )
    }

    private func updateRotation(
        nowNanoseconds: UInt64,
        allowStart: Bool
    ) {
        guard let privacyPool else { return }
        if let overlapCompletionNanoseconds,
           nowNanoseconds >= overlapCompletionNanoseconds {
            if privacyPool.completeRotation() {
                rotationCount &+= 1
                if let overlapStartedNanoseconds {
                    maximumRotationOverlapNanoseconds = max(
                        maximumRotationOverlapNanoseconds,
                        nowNanoseconds - overlapStartedNanoseconds
                    )
                }
            }
            self.overlapCompletionNanoseconds = nil
            overlapStartedNanoseconds = nil
        }
        guard allowStart,
              overlapCompletionNanoseconds == nil,
              let nextRotationNanoseconds,
              nowNanoseconds >= nextRotationNanoseconds,
              let startNanoseconds,
              nowNanoseconds >= startNanoseconds,
              configuration.durationNanoseconds -
                min(
                    configuration.durationNanoseconds,
                    nowNanoseconds - startNanoseconds
                ) >= configuration.rotationCadence.overlapNanoseconds
        else {
            return
        }
        if case let .started(_, deadline) =
            privacyPool.beginRotation(nowNanoseconds: nowNanoseconds) {
            overlapCompletionNanoseconds = deadline
            overlapStartedNanoseconds = nowNanoseconds
        }
        self.nextRotationNanoseconds = nowNanoseconds.addingClamped(
            configuration.rotationCadence.intervalNanoseconds
        )
    }

    private func emitCoverIfDue(
        scheduleNanoseconds: UInt64,
        observedNanoseconds: UInt64
    ) throws {
        guard configuration.mode == .maximumPrivacy,
              let privacyPool,
              let emission = cover.poll(
                nowNanoseconds: scheduleNanoseconds
              )
        else {
            return
        }
        let actualLateness =
            observedNanoseconds >= emission.scheduledNanoseconds
            ? observedNanoseconds - emission.scheduledNanoseconds
            : 0
        if observedNanoseconds >
            emission.scheduledNanoseconds.addingClamped(
                WCF3Constants.maximumShuffleNanoseconds
            ) {
            coverDeadlinesMissed &+= 1
        }
        maximumCoverLatenessNanoseconds = max(
            maximumCoverLatenessNanoseconds,
            actualLateness
        )
        let active =
            privacyPool.standbyCircuit() ??
            privacyPool.activeCircuit()
        let outboundAccepted = try enqueueCover(
            into: active.outboundShaper,
            sequence: nextOutboundSequence(),
            nowNanoseconds: observedNanoseconds
        )
        if outboundAccepted {
            coverOutboundCellsAccepted &+= 1
        }
        let inboundAccepted = try enqueueCover(
            into: active.inboundShaper,
            sequence: nextInboundSequence(),
            nowNanoseconds: observedNanoseconds
        )
        if inboundAccepted {
            coverInboundCellsAccepted &+= 1
        }
        if outboundAccepted && inboundAccepted {
            coverPairsAccepted &+= 1
        }
    }

    private func produceSyntheticCells(
        elapsedNanoseconds: UInt64,
        nowNanoseconds: UInt64
    ) throws {
        let producerRate = configuration.trafficProfile.producerCellsPerSecond
        guard producerRate > 0, elapsedNanoseconds > 0 else {
            return
        }
        let outboundCount = accruedCells(
            rate: producerRate,
            elapsedNanoseconds: elapsedNanoseconds,
            remainder: &outboundProductionRemainder
        )
        let inboundCount = accruedCells(
            rate: producerRate,
            elapsedNanoseconds: elapsedNanoseconds,
            remainder: &inboundProductionRemainder
        )
        try produce(
            count: outboundCount,
            inbound: false,
            nowNanoseconds: nowNanoseconds
        )
        try produce(
            count: inboundCount,
            inbound: true,
            nowNanoseconds: nowNanoseconds
        )
    }

    private func runCommonPath(
        elapsedNanoseconds: UInt64
    ) {
        let rate = configuration.trafficProfile.producerCellsPerSecond
        guard rate > 0, elapsedNanoseconds > 0 else {
            return
        }
        commonPathActiveNanoseconds &+= elapsedNanoseconds
        let perDirection = accruedCells(
            rate: rate,
            elapsedNanoseconds: elapsedNanoseconds,
            remainder: &commonPathRemainder
        )
        let total = perDirection * 2
        for _ in 0 ..< total {
            commonPathAccumulator ^=
                commonPathUnits &+ 0x9e3779b97f4a7c15
            commonPathAccumulator =
                (commonPathAccumulator << 7) |
                (commonPathAccumulator >> 57)
            commonPathUnits &+= 1
        }
    }

    private func produce(
        count: Int,
        inbound: Bool,
        nowNanoseconds: UInt64
    ) throws {
        guard count > 0 else { return }
        guard let privacyPool else { return }
        let ingress =
            privacyPool.standbyCircuit() ??
            privacyPool.activeCircuit()
        let shaper = inbound
            ? ingress.inboundShaper
            : ingress.outboundShaper
        for index in 0 ..< count {
            let sequence = inbound
                ? nextInboundSequence()
                : nextOutboundSequence()
            let accepted = try syntheticPayload.withUnsafeBytes {
                payload in
                try shaper.enqueue(
                    header: WCF3FrameHeader(
                        kind: .data,
                        context: context,
                        sequence: sequence
                    ),
                    payload: payload,
                    nowNanoseconds: nowNanoseconds,
                    scheduleWord: nextRandomWord(),
                    paddingFiller: { bytes in
                        bytes.initializeMemory(
                            as: UInt8.self,
                            repeating:
                                UInt8(truncatingIfNeeded: sequence)
                        )
                    }
                )
            }
            if !accepted {
                backpressureEvents &+= 1
                backpressuredCells &+= UInt64(count - index)
                break
            }
        }
    }

    private func enqueueCover(
        into shaper: PrivacyShaper,
        sequence: UInt64,
        nowNanoseconds: UInt64
    ) throws -> Bool {
        try shaper.enqueue(
            header: WCF3FrameHeader(
                kind: .cover,
                context: context,
                sequence: sequence
            ),
            payload: UnsafeRawBufferPointer(start: nil, count: 0),
            nowNanoseconds: nowNanoseconds,
            scheduleWord: nextRandomWord(),
            paddingFiller: { bytes in
                bytes.initializeMemory(
                    as: UInt8.self,
                    repeating: UInt8(truncatingIfNeeded: sequence)
                )
            }
        )
    }

    private func drainSyntheticCells(
        elapsedNanoseconds: UInt64,
        nowNanoseconds: UInt64
    ) throws {
        // Cover is additive to synthetic user traffic. Reserve one extra
        // cell/second/direction so low and medium remain stable instead of
        // filling a 512-cell ring before the 15-minute warmup.
        let rate = configuration.trafficProfile.drainCellsPerSecond &+ 1
        let outboundAccrued = accruedCells(
            rate: rate,
            elapsedNanoseconds: elapsedNanoseconds,
            remainder: &outboundDrainRemainder
        )
        let inboundAccrued = accruedCells(
            rate: rate,
            elapsedNanoseconds: elapsedNanoseconds,
            remainder: &inboundDrainRemainder
        )
        outboundDrainCredits = min(
            WCF3Constants.defaultRingCapacity,
            outboundDrainCredits + outboundAccrued
        )
        inboundDrainCredits = min(
            WCF3Constants.defaultRingCapacity,
            inboundDrainCredits + inboundAccrued
        )
        guard let privacyPool else { return }
        let circuits = [privacyPool.activeCircuit()] +
            (privacyPool.standbyCircuit().map { [$0] } ?? [])
        var maximumOutboundDrained = 0
        var maximumInboundDrained = 0
        for circuit in circuits {
            maximumOutboundDrained = max(
                maximumOutboundDrained,
                try drain(
                count: outboundDrainCredits,
                shaper: circuit.outboundShaper,
                nowNanoseconds: nowNanoseconds,
                inbound: false,
                scratch: &outboundScratch
                )
            )
            maximumInboundDrained = max(
                maximumInboundDrained,
                try drain(
                count: inboundDrainCredits,
                shaper: circuit.inboundShaper,
                nowNanoseconds: nowNanoseconds,
                inbound: true,
                scratch: &inboundScratch
                )
            )
        }
        outboundDrainCredits -= maximumOutboundDrained
        inboundDrainCredits -= maximumInboundDrained
    }

    private func drain(
        count: Int,
        shaper: PrivacyShaper,
        nowNanoseconds: UInt64,
        inbound: Bool,
        scratch: inout [UInt8]
    ) throws -> Int {
        guard count > 0 else { return 0 }
        var drained = 0
        for _ in 0 ..< count {
            let metadata = try scratch.withUnsafeMutableBytes {
                try shaper.dequeueEligible(
                    nowNanoseconds: nowNanoseconds,
                    selectionWord: nextRandomWord(),
                    into: $0
                )
            }
            guard let metadata else { break }
            drained += 1
            let queueDelay =
                nowNanoseconds - metadata.enqueuedAtNanoseconds
            queueDelayHistogram.record(queueDelay)
            maximumObservedQueueDelayNanoseconds = max(
                maximumObservedQueueDelayNanoseconds,
                queueDelay
            )
            if metadata.isCover {
                if inbound {
                    coverInboundCellsEmitted &+= 1
                } else {
                    coverOutboundCellsEmitted &+= 1
                }
            }
        }
        return drained
    }

    private func recordOccupancy() {
        guard let privacyPool else { return }
        let circuits = privacyPool.allCircuits()
        let inbound = circuits.map {
            $0.inbound.snapshot().occupied
        }.max() ?? 0
        let outbound = circuits.map {
            $0.outbound.snapshot().occupied
        }.max() ?? 0
        inboundOccupancyHistogram[inbound] &+= 1
        outboundOccupancyHistogram[outbound] &+= 1
        occupancySamples &+= 1
    }

    private func finalize() {
        cover.stop()
        _ = privacyPool?.cancelRotation()
        overlapCompletionNanoseconds = nil
        overlapStartedNanoseconds = nil
        completionLatched = true
    }

    private func userTrafficIsActive(
        nowNanoseconds: UInt64
    ) -> Bool {
        guard let startNanoseconds,
              nowNanoseconds >= startNanoseconds
        else {
            return false
        }
        return nowNanoseconds - startNanoseconds <
            configuration.trafficActiveNanoseconds
    }

    private func quantile99(_ histogram: [UInt64]) -> Int {
        guard occupancySamples > 0 else { return 0 }
        let target = (occupancySamples &* 99 &+ 99) / 100
        var cumulative: UInt64 = 0
        for (value, count) in histogram.enumerated() {
            cumulative &+= count
            if cumulative >= target {
                return value
            }
        }
        return histogram.count - 1
    }

    private func accruedCells(
        rate: UInt64,
        elapsedNanoseconds: UInt64,
        remainder: inout UInt64
    ) -> Int {
        let numerator = remainder &+ rate &* elapsedNanoseconds
        remainder = numerator % Self.nanosecondsPerSecond
        return Int(numerator / Self.nanosecondsPerSecond)
    }

    private func nextOutboundSequence() -> UInt64 {
        defer { outboundSequence &+= 1 }
        return outboundSequence
    }

    private func nextInboundSequence() -> UInt64 {
        defer { inboundSequence &+= 1 }
        return inboundSequence
    }

    private func nextRandomWord() -> UInt64 {
        randomState ^= randomState << 13
        randomState ^= randomState >> 7
        randomState ^= randomState << 17
        return randomState
    }
}

/// Fixed-memory 100-microsecond delay histogram. The overflow bucket makes
/// delays over 100 ms fail closed, while a separate exact counter determines
/// whether more than one percent of samples exceeded the 25 ms gate.
private struct BoundedDelayHistogram {
    private static let bucketWidthNanoseconds: UInt64 = 100_000
    private static let boundedBucketCount = 1_001
    private var buckets = [UInt64](
        repeating: 0,
        count: boundedBucketCount + 1
    )
    private(set) var sampleCount: UInt64 = 0
    private(set) var over25Milliseconds: UInt64 = 0

    mutating func record(_ nanoseconds: UInt64) {
        let raw = nanoseconds / Self.bucketWidthNanoseconds
        let index = raw >= UInt64(Self.boundedBucketCount)
            ? Self.boundedBucketCount
            : Int(raw)
        buckets[index] &+= 1
        sampleCount &+= 1
        if nanoseconds > 25_000_000 {
            over25Milliseconds &+= 1
        }
    }

    var quantile99UpperBound: UInt64 {
        guard sampleCount > 0 else { return 0 }
        let target = (sampleCount &* 99 &+ 99) / 100
        var cumulative: UInt64 = 0
        for (index, count) in buckets.enumerated() {
            cumulative &+= count
            if cumulative >= target {
                guard index < Self.boundedBucketCount else {
                    return UInt64.max
                }
                return UInt64(index + 1) &*
                    Self.bucketWidthNanoseconds
            }
        }
        return UInt64.max
    }
}

private extension SyntheticTrafficProfile {
    var producerCellsPerSecond: UInt64 {
        switch self {
        case .idle:
            return 0
        case .low:
            return 50
        case .medium:
            return 1_250
        case .saturated:
            return 5_000
        }
    }

    var drainCellsPerSecond: UInt64 {
        switch self {
        case .idle:
            return 16
        case .low:
            return 50
        case .medium, .saturated:
            return 1_250
        }
    }
}

private extension UInt64 {
    func addingClamped(_ other: UInt64) -> UInt64 {
        let (value, overflow) = addingReportingOverflow(other)
        return overflow ? UInt64.max : value
    }
}
