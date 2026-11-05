import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum SpikeMode: String, Codable, Sendable {
    case coreBaseline = "core-baseline"
    case maximumPrivacy = "maximum-privacy"
}

public enum SyntheticTrafficProfile: String, Codable, Sendable {
    case idle
    case low
    case medium
    case saturated
}

public struct SpikeConstantsSnapshot: Codable, Equatable, Sendable {
    public let cellBytes: Int
    public let payloadBytes: Int
    public let ringCapacityPerDirection: Int
    public let maximumCircuits: Int
    public let shuffleNanoseconds: UInt64
    public let coverIntervalNanoseconds: UInt64
    public let coverTailNanoseconds: UInt64
    public let circuitRotationNanoseconds: UInt64
    public let spikeOverlapNanoseconds: UInt64

    public init(
        ringCapacityPerDirection: Int =
            WCF3Constants.defaultRingCapacity
    ) {
        cellBytes = WCF3Constants.privacyCellSize
        payloadBytes = WCF3Constants.privacyPayloadSize
        self.ringCapacityPerDirection = ringCapacityPerDirection
        maximumCircuits = WCF3Constants.maximumConcurrentCircuits
        shuffleNanoseconds =
            WCF3Constants.maximumShuffleNanoseconds
        coverIntervalNanoseconds =
            WCF3Constants.coverIntervalNanoseconds
        coverTailNanoseconds =
            WCF3Constants.coverTailNanoseconds
        circuitRotationNanoseconds =
            WCF3Constants.circuitRotationNanoseconds
        spikeOverlapNanoseconds =
            WCF3Constants.spikeRotationOverlapNanoseconds
    }
}

public struct SpikeResourceSnapshot: Codable, Equatable, Sendable {
    public let residentBytes: UInt64?
    public let physicalFootprintBytes: UInt64?
    public let availableProcessBytes: UInt64?
    public let userCPUNanoseconds: UInt64?
    public let systemCPUNanoseconds: UInt64?
    public let interruptWakeups: UInt64?
    public let packageIdleWakeups: UInt64?
    public let energyNanojoules: UInt64?
    public let thermalState: String?
    public let lowPowerMode: Bool?

    public init(
        residentBytes: UInt64? = nil,
        physicalFootprintBytes: UInt64? = nil,
        availableProcessBytes: UInt64? = nil,
        userCPUNanoseconds: UInt64? = nil,
        systemCPUNanoseconds: UInt64? = nil,
        interruptWakeups: UInt64? = nil,
        packageIdleWakeups: UInt64? = nil,
        energyNanojoules: UInt64? = nil,
        thermalState: String? = nil,
        lowPowerMode: Bool? = nil
    ) {
        self.residentBytes = residentBytes
        self.physicalFootprintBytes = physicalFootprintBytes
        self.availableProcessBytes = availableProcessBytes
        self.userCPUNanoseconds = userCPUNanoseconds
        self.systemCPUNanoseconds = systemCPUNanoseconds
        self.interruptWakeups = interruptWakeups
        self.packageIdleWakeups = packageIdleWakeups
        self.energyNanojoules = energyNanojoules
        self.thermalState = thermalState
        self.lowPowerMode = lowPowerMode
    }
}

public struct SpikeResourceWindowSnapshot:
    Codable, Equatable, Sendable
{
    public let firstSampleMonotonicNanoseconds: UInt64
    public let lastSampleMonotonicNanoseconds: UInt64
    public let sampleCount: UInt64
    public let scheduledSampleCount: UInt64
    public let peakResidentBytes: UInt64?
    public let peakPhysicalFootprintBytes: UInt64?
    public let minimumAvailableProcessBytes: UInt64?
    public let userCPUDeltaNanoseconds: UInt64?
    public let systemCPUDeltaNanoseconds: UInt64?
    public let interruptWakeupDelta: UInt64?
    public let packageIdleWakeupDelta: UInt64?
    public let energyDeltaNanojoules: UInt64?
    public let worstThermalState: String?
    public let lowPowerModeObserved: Bool
    public let lowPowerModeAlwaysEnabled: Bool

    public init(
        firstSampleMonotonicNanoseconds: UInt64,
        lastSampleMonotonicNanoseconds: UInt64,
        sampleCount: UInt64,
        scheduledSampleCount: UInt64,
        peakResidentBytes: UInt64?,
        peakPhysicalFootprintBytes: UInt64?,
        minimumAvailableProcessBytes: UInt64?,
        userCPUDeltaNanoseconds: UInt64?,
        systemCPUDeltaNanoseconds: UInt64?,
        interruptWakeupDelta: UInt64?,
        packageIdleWakeupDelta: UInt64?,
        energyDeltaNanojoules: UInt64?,
        worstThermalState: String?,
        lowPowerModeObserved: Bool,
        lowPowerModeAlwaysEnabled: Bool
    ) {
        self.firstSampleMonotonicNanoseconds =
            firstSampleMonotonicNanoseconds
        self.lastSampleMonotonicNanoseconds =
            lastSampleMonotonicNanoseconds
        self.sampleCount = sampleCount
        self.scheduledSampleCount = scheduledSampleCount
        self.peakResidentBytes = peakResidentBytes
        self.peakPhysicalFootprintBytes =
            peakPhysicalFootprintBytes
        self.minimumAvailableProcessBytes =
            minimumAvailableProcessBytes
        self.userCPUDeltaNanoseconds = userCPUDeltaNanoseconds
        self.systemCPUDeltaNanoseconds = systemCPUDeltaNanoseconds
        self.interruptWakeupDelta = interruptWakeupDelta
        self.packageIdleWakeupDelta = packageIdleWakeupDelta
        self.energyDeltaNanojoules = energyDeltaNanojoules
        self.worstThermalState = worstThermalState
        self.lowPowerModeObserved = lowPowerModeObserved
        self.lowPowerModeAlwaysEnabled =
            lowPowerModeAlwaysEnabled
    }
}

/// Bounded online aggregation for the extension's one-hertz samples. It keeps
/// first/last counters and extrema, never an unbounded sample array.
public struct SpikeResourceWindowAccumulator: Sendable {
    private var firstTime: UInt64?
    private var lastTime: UInt64?
    private var sampleCount: UInt64 = 0
    private var scheduledSampleCount: UInt64 = 0
    private var first: SpikeResourceSnapshot?
    private var last: SpikeResourceSnapshot?
    private var peakResidentBytes: UInt64?
    private var peakPhysicalFootprintBytes: UInt64?
    private var minimumAvailableProcessBytes: UInt64?
    private var worstThermalState: String?
    private var worstThermalRank = -1
    private var lowPowerModeObserved = false
    private var lowPowerModeAlwaysEnabled = true

    public init() {}

    public var isEmpty: Bool { sampleCount == 0 }

    public mutating func add(
        _ sample: SpikeResourceSnapshot,
        monotonicNanoseconds: UInt64,
        scheduledSamples: UInt64 = 1
    ) {
        if first == nil {
            first = sample
            firstTime = monotonicNanoseconds
        }
        last = sample
        lastTime = monotonicNanoseconds
        sampleCount &+= 1
        scheduledSampleCount &+= max(1, scheduledSamples)
        peakResidentBytes = maximum(
            peakResidentBytes,
            sample.residentBytes
        )
        peakPhysicalFootprintBytes = maximum(
            peakPhysicalFootprintBytes,
            sample.physicalFootprintBytes
        )
        minimumAvailableProcessBytes = minimum(
            minimumAvailableProcessBytes,
            sample.availableProcessBytes
        )
        if let thermal = sample.thermalState {
            let rank = Self.thermalRank(thermal)
            if rank > worstThermalRank {
                worstThermalRank = rank
                worstThermalState = thermal
            }
        }
        if sample.lowPowerMode == true {
            lowPowerModeObserved = true
        }
        if sample.lowPowerMode != true {
            lowPowerModeAlwaysEnabled = false
        }
    }

    public mutating func finish() -> SpikeResourceWindowSnapshot? {
        guard let firstTime, let lastTime, let first, let last else {
            return nil
        }
        let result = SpikeResourceWindowSnapshot(
            firstSampleMonotonicNanoseconds: firstTime,
            lastSampleMonotonicNanoseconds: lastTime,
            sampleCount: sampleCount,
            scheduledSampleCount: scheduledSampleCount,
            peakResidentBytes: peakResidentBytes,
            peakPhysicalFootprintBytes: peakPhysicalFootprintBytes,
            minimumAvailableProcessBytes:
                minimumAvailableProcessBytes,
            userCPUDeltaNanoseconds: delta(
                first.userCPUNanoseconds,
                last.userCPUNanoseconds
            ),
            systemCPUDeltaNanoseconds: delta(
                first.systemCPUNanoseconds,
                last.systemCPUNanoseconds
            ),
            interruptWakeupDelta: delta(
                first.interruptWakeups,
                last.interruptWakeups
            ),
            packageIdleWakeupDelta: delta(
                first.packageIdleWakeups,
                last.packageIdleWakeups
            ),
            energyDeltaNanojoules: delta(
                first.energyNanojoules,
                last.energyNanojoules
            ),
            worstThermalState: worstThermalState,
            lowPowerModeObserved: lowPowerModeObserved,
            lowPowerModeAlwaysEnabled:
                lowPowerModeAlwaysEnabled
        )
        self = SpikeResourceWindowAccumulator()
        return result
    }

    private func maximum(
        _ first: UInt64?,
        _ second: UInt64?
    ) -> UInt64? {
        switch (first, second) {
        case let (.some(a), .some(b)): return max(a, b)
        case let (.some(a), .none): return a
        case let (.none, .some(b)): return b
        case (.none, .none): return nil
        }
    }

    private func minimum(
        _ first: UInt64?,
        _ second: UInt64?
    ) -> UInt64? {
        switch (first, second) {
        case let (.some(a), .some(b)): return min(a, b)
        case let (.some(a), .none): return a
        case let (.none, .some(b)): return b
        case (.none, .none): return nil
        }
    }

    private func delta(
        _ first: UInt64?,
        _ last: UInt64?
    ) -> UInt64? {
        guard let first, let last, last >= first else { return nil }
        return last - first
    }

    private static func thermalRank(_ state: String) -> Int {
        switch state {
        case "nominal": return 0
        case "fair": return 1
        case "serious": return 2
        case "critical": return 3
        default: return -1
        }
    }
}

public struct SpikeDataPathSnapshot: Codable, Equatable, Sendable {
    public let allocatedPrivacyCellBytes: Int
    public let inboundQueueDepth: Int
    public let outboundQueueDepth: Int
    public let inboundHighWatermark: Int
    public let outboundHighWatermark: Int
    public let occupancySamples: UInt64
    public let inboundOccupancyP99Cells: Int
    public let outboundOccupancyP99Cells: Int
    public let acceptedCells: UInt64
    public let emittedCells: UInt64
    public let droppedCells: UInt64
    public let retiredDataCells: UInt64
    public let retiredCoverCells: UInt64
    public let commonPathUnits: UInt64
    public let commonPathActiveNanoseconds: UInt64
    public let commonPathChecksum: UInt64
    public let coverPairsAccepted: UInt64
    public let coverInboundCellsAccepted: UInt64
    public let coverOutboundCellsAccepted: UInt64
    public let coverPairsEmitted: UInt64
    public let coverInboundCellsEmitted: UInt64
    public let coverOutboundCellsEmitted: UInt64
    public let coverInboundCellsPending: Int
    public let coverOutboundCellsPending: Int
    public let coverInboundCellsRetired: UInt64
    public let coverOutboundCellsRetired: UInt64
    public let coverDeadlinesMissed: UInt64
    public let maximumCoverLatenessNanoseconds: UInt64
    public let queueDelaySamples: UInt64
    public let queueDelayP99UpperBoundNanoseconds: UInt64
    public let queueDelayOver25Milliseconds: UInt64
    public let maximumObservedQueueDelayNanoseconds: UInt64
    public let unaccountedWorkNanoseconds: UInt64
    public let backpressureEvents: UInt64
    public let backpressuredCells: UInt64
    public let rotationCount: UInt64
    public let maximumRotationOverlapNanoseconds: UInt64
    public let rotationActiveCircuit: Int?
    public let rotationStandbyCircuit: Int?
    public let rotationOverlapDeadlineNanoseconds: UInt64?

    public init(
        allocatedPrivacyCellBytes: Int = 0,
        inboundQueueDepth: Int,
        outboundQueueDepth: Int,
        inboundHighWatermark: Int,
        outboundHighWatermark: Int,
        occupancySamples: UInt64,
        inboundOccupancyP99Cells: Int,
        outboundOccupancyP99Cells: Int,
        acceptedCells: UInt64,
        emittedCells: UInt64,
        droppedCells: UInt64,
        retiredDataCells: UInt64,
        retiredCoverCells: UInt64,
        commonPathUnits: UInt64,
        commonPathActiveNanoseconds: UInt64,
        commonPathChecksum: UInt64,
        coverPairsAccepted: UInt64,
        coverInboundCellsAccepted: UInt64,
        coverOutboundCellsAccepted: UInt64,
        coverPairsEmitted: UInt64,
        coverInboundCellsEmitted: UInt64,
        coverOutboundCellsEmitted: UInt64,
        coverInboundCellsPending: Int,
        coverOutboundCellsPending: Int,
        coverInboundCellsRetired: UInt64,
        coverOutboundCellsRetired: UInt64,
        coverDeadlinesMissed: UInt64,
        maximumCoverLatenessNanoseconds: UInt64,
        queueDelaySamples: UInt64,
        queueDelayP99UpperBoundNanoseconds: UInt64,
        queueDelayOver25Milliseconds: UInt64,
        maximumObservedQueueDelayNanoseconds: UInt64,
        unaccountedWorkNanoseconds: UInt64,
        backpressureEvents: UInt64,
        backpressuredCells: UInt64,
        rotationCount: UInt64,
        maximumRotationOverlapNanoseconds: UInt64,
        rotationActiveCircuit: Int?,
        rotationStandbyCircuit: Int?,
        rotationOverlapDeadlineNanoseconds: UInt64?
    ) {
        self.allocatedPrivacyCellBytes = allocatedPrivacyCellBytes
        self.inboundQueueDepth = inboundQueueDepth
        self.outboundQueueDepth = outboundQueueDepth
        self.inboundHighWatermark = inboundHighWatermark
        self.outboundHighWatermark = outboundHighWatermark
        self.occupancySamples = occupancySamples
        self.inboundOccupancyP99Cells = inboundOccupancyP99Cells
        self.outboundOccupancyP99Cells = outboundOccupancyP99Cells
        self.acceptedCells = acceptedCells
        self.emittedCells = emittedCells
        self.droppedCells = droppedCells
        self.retiredDataCells = retiredDataCells
        self.retiredCoverCells = retiredCoverCells
        self.commonPathUnits = commonPathUnits
        self.commonPathActiveNanoseconds =
            commonPathActiveNanoseconds
        self.commonPathChecksum = commonPathChecksum
        self.coverPairsAccepted = coverPairsAccepted
        self.coverInboundCellsAccepted = coverInboundCellsAccepted
        self.coverOutboundCellsAccepted = coverOutboundCellsAccepted
        self.coverPairsEmitted = coverPairsEmitted
        self.coverInboundCellsEmitted = coverInboundCellsEmitted
        self.coverOutboundCellsEmitted = coverOutboundCellsEmitted
        self.coverInboundCellsPending = coverInboundCellsPending
        self.coverOutboundCellsPending = coverOutboundCellsPending
        self.coverInboundCellsRetired = coverInboundCellsRetired
        self.coverOutboundCellsRetired = coverOutboundCellsRetired
        self.coverDeadlinesMissed = coverDeadlinesMissed
        self.maximumCoverLatenessNanoseconds =
            maximumCoverLatenessNanoseconds
        self.queueDelaySamples = queueDelaySamples
        self.queueDelayP99UpperBoundNanoseconds =
            queueDelayP99UpperBoundNanoseconds
        self.queueDelayOver25Milliseconds =
            queueDelayOver25Milliseconds
        self.maximumObservedQueueDelayNanoseconds =
            maximumObservedQueueDelayNanoseconds
        self.unaccountedWorkNanoseconds = unaccountedWorkNanoseconds
        self.backpressureEvents = backpressureEvents
        self.backpressuredCells = backpressuredCells
        self.rotationCount = rotationCount
        self.maximumRotationOverlapNanoseconds =
            maximumRotationOverlapNanoseconds
        self.rotationActiveCircuit = rotationActiveCircuit
        self.rotationStandbyCircuit = rotationStandbyCircuit
        self.rotationOverlapDeadlineNanoseconds =
            rotationOverlapDeadlineNanoseconds
    }
}

public struct RotationResourceSnapshot:
    Codable, Equatable, Sendable
{
    public let samples: UInt64
    public let lastRotationCount: UInt64
    public let firstTenPeakResidentBytes: UInt64?
    public let firstTenPeakPhysicalFootprintBytes: UInt64?
    public let postTenPeakResidentBytes: UInt64?
    public let postTenPeakPhysicalFootprintBytes: UInt64?

    public init(
        samples: UInt64,
        lastRotationCount: UInt64,
        firstTenPeakResidentBytes: UInt64?,
        firstTenPeakPhysicalFootprintBytes: UInt64?,
        postTenPeakResidentBytes: UInt64?,
        postTenPeakPhysicalFootprintBytes: UInt64?
    ) {
        self.samples = samples
        self.lastRotationCount = lastRotationCount
        self.firstTenPeakResidentBytes = firstTenPeakResidentBytes
        self.firstTenPeakPhysicalFootprintBytes =
            firstTenPeakPhysicalFootprintBytes
        self.postTenPeakResidentBytes = postTenPeakResidentBytes
        self.postTenPeakPhysicalFootprintBytes =
            postTenPeakPhysicalFootprintBytes
    }
}

public struct SpikeMetricRecord: Codable, Equatable, Sendable {
    public let schema: String
    public let protocolVersion: String
    public let frameVersion: String
    public let platform: String
    public let osVersion: String
    public let hardwareModel: String
    public let runID: String
    public let event: String
    public let monotonicNanoseconds: UInt64
    public let wallTimeUTC: String
    public let mode: SpikeMode
    public let trafficProfile: SyntheticTrafficProfile
    public let coverSemantics: CoverTrafficSemantics
    public let rotationCadence: StageARotationCadence
    public let testCondition: StageATestCondition
    public let pairID: String
    public let durationNanoseconds: UInt64
    public let trafficActiveNanoseconds: UInt64
    public let sourceDigest: String
    public let artifactDigest: String
    public let constants: SpikeConstantsSnapshot
    public let resources: SpikeResourceSnapshot?
    public let resourceWindow: SpikeResourceWindowSnapshot?
    public let wholeRunResourceWindow: SpikeResourceWindowSnapshot?
    public let dataPath: SpikeDataPathSnapshot?
    public let rotationResources: RotationResourceSnapshot?
    public let controlLatencyNanoseconds: UInt64?
    /// Present only on the first `started` record, which is the record whose
    /// exact bytes the host start receipt pins. `providerReadyAt` is
    /// deliberately NOT here: it is captured after this record has been
    /// written and hashed, so it can only live in the attestation and the
    /// receipt.
    public let startAttemptNonce: String?
    public let startRequestedAtMonotonicNanoseconds: UInt64?
    public let providerReceivedAtMonotonicNanoseconds: UInt64?
    public let failureCode: String?

    public init(
        runID: String,
        event: String,
        monotonicNanoseconds: UInt64,
        wallTimeUTC: String,
        platform: String = "ios",
        osVersion: String = "fixture-ios",
        hardwareModel: String = "fixture-iphone",
        mode: SpikeMode,
        trafficProfile: SyntheticTrafficProfile,
        coverSemantics: CoverTrafficSemantics,
        rotationCadence: StageARotationCadence,
        testCondition: StageATestCondition =
            .foregroundWiFi,
        pairID: String =
            "01234567-89ab-cdef-0123-456789abcdef",
        durationNanoseconds: UInt64,
        trafficActiveNanoseconds: UInt64,
        sourceDigest: String,
        artifactDigest: String,
        constants: SpikeConstantsSnapshot =
            SpikeConstantsSnapshot(),
        resources: SpikeResourceSnapshot? = nil,
        resourceWindow: SpikeResourceWindowSnapshot? = nil,
        wholeRunResourceWindow: SpikeResourceWindowSnapshot? = nil,
        dataPath: SpikeDataPathSnapshot? = nil,
        rotationResources: RotationResourceSnapshot? = nil,
        controlLatencyNanoseconds: UInt64? = nil,
        startAttemptNonce: String? = nil,
        startRequestedAtMonotonicNanoseconds: UInt64? = nil,
        providerReceivedAtMonotonicNanoseconds: UInt64? = nil,
        failureCode: String? = nil
    ) throws {
        guard Self.validIdentifier(runID),
              Self.validEvent(event),
              Self.validDigest(sourceDigest),
              Self.validDigest(artifactDigest),
              Self.validLabel(platform),
              Self.validLabel(osVersion),
              Self.validLabel(hardwareModel)
        else {
            throw SpikeMetricError.invalidRecordIdentity
        }
        // The three start-attempt fields are one indivisible binding: a record
        // carrying some of them proves nothing.
        let startFieldsPresent = [
            startAttemptNonce != nil,
            startRequestedAtMonotonicNanoseconds != nil,
            providerReceivedAtMonotonicNanoseconds != nil,
        ]
        guard startFieldsPresent.allSatisfy({ $0 }) ||
            startFieldsPresent.allSatisfy({ !$0 })
        else {
            throw SpikeMetricError.invalidStartAttemptBinding
        }
        if let startAttemptNonce {
            guard StartLatencyValidation
                .isLowercaseUUID(startAttemptNonce),
                let requested = startRequestedAtMonotonicNanoseconds,
                let received = providerReceivedAtMonotonicNanoseconds,
                received >= requested
            else {
                throw SpikeMetricError.invalidStartAttemptBinding
            }
        }
        schema = WCF3Constants.schemaVersion
        protocolVersion = WCF3Constants.protocolVersion
        frameVersion = WCF3Constants.frameVersion
        self.platform = platform
        self.osVersion = osVersion
        self.hardwareModel = hardwareModel
        self.runID = runID
        self.event = event
        self.monotonicNanoseconds = monotonicNanoseconds
        self.wallTimeUTC = wallTimeUTC
        self.mode = mode
        self.trafficProfile = trafficProfile
        self.coverSemantics = coverSemantics
        self.rotationCadence = rotationCadence
        self.testCondition = testCondition
        self.pairID = pairID
        self.durationNanoseconds = durationNanoseconds
        self.trafficActiveNanoseconds = trafficActiveNanoseconds
        self.sourceDigest = sourceDigest
        self.artifactDigest = artifactDigest
        self.constants = constants
        self.resources = resources
        self.resourceWindow = resourceWindow
        self.wholeRunResourceWindow = wholeRunResourceWindow
        self.dataPath = dataPath
        self.rotationResources = rotationResources
        self.controlLatencyNanoseconds = controlLatencyNanoseconds
        self.startAttemptNonce = startAttemptNonce
        self.startRequestedAtMonotonicNanoseconds =
            startRequestedAtMonotonicNanoseconds
        self.providerReceivedAtMonotonicNanoseconds =
            providerReceivedAtMonotonicNanoseconds
        self.failureCode = failureCode
    }

    private static func validIdentifier(_ value: String) -> Bool {
        guard (16 ... 128).contains(value.count) else { return false }
        return value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) ||
                ($0 >= 97 && $0 <= 122) ||
                $0 == 45
        }
    }

    private static func validEvent(_ value: String) -> Bool {
        guard (1 ... 64).contains(value.count) else { return false }
        return value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) ||
                ($0 >= 97 && $0 <= 122) ||
                $0 == 45 || $0 == 95
        }
    }

    private static func validDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private static func validLabel(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256 &&
            !value.utf8.contains(0)
    }
}

public enum SpikeMetricError: Error, Equatable {
    case invalidRecordIdentity
    case invalidStartAttemptBinding
    case evidencePathExistsOrIsUnsafe
    case evidenceWriterPoisoned
    case notTheFirstRecord
    case firstRecordAlreadyRecorded
    case directoryCreationFailed(Int32)
    case fileSynchronizeFailed(Int32)
    case directorySynchronizeFailed(Int32)
    case durabilityBarrierUnavailable
}

// MARK: - Durability barrier

/// Which storage barrier a synchronize actually obtained.
///
/// READ THE CLAIM CAREFULLY, it is deliberately narrow. On Darwin `fsync(2)`
/// moves the data out of the kernel to the drive but explicitly does NOT ask
/// the drive to flush its own write cache; Apple documents `F_FULLFSYNC` as
/// the call that additionally requests that flush. So:
///
/// - `.fullFsync` means the strongest barrier this platform exposes was
///   accepted for that descriptor. It is not an absolute power-loss guarantee:
///   a drive may still not honour the flush request, and this code has no way
///   to observe whether it did.
/// - `.fsyncOnly` means `F_FULLFSYNC` was refused by the filesystem and plain
///   `fsync` was used. The bytes left the kernel; they may still be sitting in
///   a volatile device cache. NO power-loss claim is made in this case.
///
/// The value is recorded rather than swallowed so that a caller — and a
/// reader of this source — can see which of the two actually happened instead
/// of being told a barrier was obtained that was not.
public enum SpikeDurabilityBarrier: String, Equatable, Sendable {
    case fullFsync = "f-fullfsync"
    case fsyncOnly = "fsync-only"

    /// The weaker of two barriers, for combining a file and its directory.
    public func combined(with other: SpikeDurabilityBarrier)
        -> SpikeDurabilityBarrier
    {
        self == .fullFsync && other == .fullFsync ? .fullFsync : .fsyncOnly
    }
}

/// POSIX durability seams shared by the evidence writer.
///
/// `Host/ImmutableReceiptStore.swift` carries its own copy of the same logic
/// on purpose: `Scripts/immutable_receipt_store_fixture.swift` compiles that
/// file standalone against Darwin and Foundation only, with no access to this
/// package, so the store cannot import these. The duplication is deliberate
/// and both copies must be kept in step.
enum SpikeDurability {
    /// `fsync` and `fcntl(F_FULLFSYNC)` are interruptible; `close` is not
    /// retryable on Darwin, where the descriptor is released even when EINTR
    /// is reported, so retrying it could close an unrelated descriptor.
    static func synchronize(
        descriptor: Int32
    ) -> (barrier: SpikeDurabilityBarrier, failure: Int32?) {
        while true {
            if fcntl(descriptor, F_FULLFSYNC) == 0 {
                return (.fullFsync, nil)
            }
            let failure = errno
            if failure == EINTR { continue }
            // Only a refusal of the operation itself falls back. A real I/O
            // error must surface as an error, not be retried as a weaker
            // barrier that then reports success.
            guard failure == ENOTSUP || failure == EINVAL ||
                failure == ENOTTY || failure == EOPNOTSUPP ||
                failure == EPERM || failure == EBADF
            else {
                return (.fsyncOnly, failure)
            }
            break
        }
        while true {
            if fsync(descriptor) == 0 { return (.fsyncOnly, nil) }
            let failure = errno
            if failure == EINTR { continue }
            return (.fsyncOnly, failure)
        }
    }

    /// Opens `directory` refusing a symbolic link in its FINAL component and
    /// requiring the result to be a directory.
    ///
    /// What this does not do, stated rather than implied: Darwin's
    /// `O_NOFOLLOW_ANY`, which would refuse a symbolic link anywhere on the
    /// path, is not usable here. Ordinary paths on this platform legitimately
    /// traverse system symbolic links — `/var` is one, and every temporary and
    /// app-group container path goes through it — so requiring
    /// `O_NOFOLLOW_ANY` refuses the real evidence directory with `ELOOP`. This
    /// was measured, not assumed. Intermediate components are therefore
    /// resolved by the kernel as usual and are NOT protected against
    /// substitution; only the final component is.
    static func synchronizeDirectory(
        _ directory: URL
    ) throws -> SpikeDurabilityBarrier {
        var descriptor: Int32 = -1
        while true {
            descriptor = directory.path.withCString {
                open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            }
            if descriptor >= 0 { break }
            let failure = errno
            if failure == EINTR { continue }
            throw SpikeMetricError.directorySynchronizeFailed(failure)
        }
        defer { close(descriptor) }
        let result = synchronize(descriptor: descriptor)
        if let failure = result.failure {
            throw SpikeMetricError.directorySynchronizeFailed(failure)
        }
        return result.barrier
    }

    /// Creates every missing component of `directory` and returns them
    /// shallowest first, so the caller knows exactly which directory entries
    /// it is responsible for making durable.
    static func createDirectoryChain(_ directory: URL) throws -> [URL] {
        var missing: [URL] = []
        var cursor = directory.standardizedFileURL
        while !FileManager.default.fileExists(atPath: cursor.path) {
            missing.append(cursor)
            let parent = cursor.deletingLastPathComponent().standardizedFileURL
            if parent.path == cursor.path { break }
            cursor = parent
        }
        let ordered = Array(missing.reversed())
        for url in ordered {
            while true {
                let made = url.path.withCString { mkdir($0, S_IRWXU) }
                if made == 0 { break }
                let failure = errno
                if failure == EINTR { continue }
                if failure == EEXIST { break }
                throw SpikeMetricError.directoryCreationFailed(failure)
            }
        }
        return ordered
    }

    /// Every directory whose ENTRIES must be synchronized for a file at
    /// `fileURL` to be reachable after a crash: the file's own parent, plus
    /// the container of each directory that had to be created.
    static func directorySyncTargets(
        fileParent: URL,
        created: [URL]
    ) -> [URL] {
        var targets: [URL] = []
        var seen: Set<String> = []
        for url in created.map({
            $0.deletingLastPathComponent().standardizedFileURL
        }) + [fileParent.standardizedFileURL] {
            if seen.insert(url.path).inserted { targets.append(url) }
        }
        return targets
    }
}

/// Append-only local JSONL. The host collector must hash and import this into
/// Winn's authenticated measurement store; this raw file is not itself an
/// authenticated score receipt.
public final class JSONLEvidenceWriter {
    private let handle: FileHandle
    /// Retained for the writer's lifetime so the first-record directory
    /// barrier applies to the exact parent in which `openat` created the file,
    /// even if a pathname is replaced before the durable append.
    private let parentDescriptor: Int32
    private let fileParent: URL
    private let encoder: JSONEncoder
    private let lock = NSLock()
    private var poisoned = false
    private var firstRecord: (digest: String, byteCount: UInt64)?
    private var directoryEntriesSynchronized = false
    private var barrier: SpikeDurabilityBarrier?

    /// Every directory whose entries must be durable for the evidence file to
    /// be reachable after a crash: the run directory itself plus the container
    /// of each directory this writer had to create.
    private let directorySyncTargets: [URL]

    /// Test seam. `nil` in production, where the primary durability barrier is
    /// the real file synchronize. Only that primary call is routed through the
    /// seam; the rollback path after a failed write always uses the real
    /// synchronize, so an injected failure produces a propagated error over a
    /// truncated file rather than a poisoned writer.
    var synchronizeHook: (() throws -> Void)?

    /// Test seam for the DIRECTORY half of the barrier, kept separate from
    /// `synchronizeHook` so a directory-sync failure can be injected on its
    /// own — with the file synchronize genuinely succeeding — and the
    /// consequences observed independently.
    var directorySynchronizeHook: ((URL) throws -> Void)?

    /// SHA-256 of the exact bytes of the first record, INCLUDING its trailing
    /// line feed, together with that byte count. `nil` until a first record
    /// has been durably appended — meaning both the file's contents and the
    /// directory entries leading to it were synchronized.
    public var firstRecordDigest: (digest: String, byteCount: UInt64)? {
        withLock { firstRecord }
    }

    /// Which barrier the durable append actually obtained. See
    /// `SpikeDurabilityBarrier`: `.fsyncOnly` carries no power-loss claim.
    public var durabilityBarrier: SpikeDurabilityBarrier? {
        withLock { barrier }
    }

    /// The directories this writer must keep durable. Exposed so a test can
    /// assert the set is derived from what was actually created rather than
    /// assumed.
    var synchronizedDirectories: [URL] { directorySyncTargets }

    public init(fileURL: URL) throws {
        let parent =
            fileURL.deletingLastPathComponent().standardizedFileURL
        let name = fileURL.lastPathComponent
        guard !name.isEmpty, name != ".", name != "..",
              !name.contains("/"), !name.utf8.contains(0)
        else {
            throw SpikeMetricError.evidencePathExistsOrIsUnsafe
        }
        let created = try SpikeDurability.createDirectoryChain(parent)
        directorySyncTargets = SpikeDurability.directorySyncTargets(
            fileParent: parent,
            created: created
        )
        var parentFD: Int32 = -1
        while true {
            parentFD = parent.path.withCString {
                open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            }
            if parentFD >= 0 { break }
            if errno == EINTR { continue }
            throw SpikeMetricError.evidencePathExistsOrIsUnsafe
        }
        var descriptor: Int32 = -1
        while true {
            descriptor = name.withCString {
                openat(
                    parentFD,
                    $0,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                    S_IRUSR | S_IWUSR
                )
            }
            if descriptor >= 0 { break }
            if errno == EINTR { continue }
            _ = close(parentFD)
            throw SpikeMetricError.evidencePathExistsOrIsUnsafe
        }
        parentDescriptor = parentFD
        fileParent = parent
        handle = FileHandle(
            fileDescriptor: descriptor,
            closeOnDealloc: true
        )
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    }

    deinit {
        try? handle.close()
        // Darwin releases a descriptor even if close reports EINTR; never
        // retry and risk closing a later, unrelated descriptor.
        _ = close(parentDescriptor)
    }

    public func append(
        _ record: SpikeMetricRecord,
        synchronize: Bool = false
    ) throws {
        try withLock {
            _ = try appendLocked(record, synchronize: synchronize)
        }
    }

    /// Durably appends the run's FIRST record and returns the SHA-256 of the
    /// exact bytes written, including the trailing line feed.
    ///
    /// The file was opened `O_CREAT|O_EXCL|O_NOFOLLOW` and this refuses to run
    /// at any offset but zero, so the buffer that is hashed is byte-for-byte
    /// the file's first line. `FileHandle.write(contentsOf:)` either writes
    /// the whole buffer or throws, and both halves of the barrier — the file's
    /// contents AND the directory entries that make the file reachable — must
    /// succeed before a digest exists. Either failure is propagated rather
    /// than swallowed, so a caller that receives a digest has a first record
    /// whose bytes and name both completed the requested barriers, with the
    /// actual strongest/weakest outcome exposed separately. `.fsyncOnly`
    /// remains explicitly outside any power-loss claim.
    ///
    /// A file that is fully synchronized but whose directory entry is not is
    /// exactly the case that loses the whole run on a crash, which is why the
    /// digest is computed after the directory half rather than before it.
    @discardableResult
    public func appendFirstRecordDurably(
        _ record: SpikeMetricRecord
    ) throws -> (digest: String, byteCount: UInt64) {
        try withLock {
            guard firstRecord == nil else {
                throw SpikeMetricError.firstRecordAlreadyRecorded
            }
            guard try handle.offset() == 0 else {
                throw SpikeMetricError.notTheFirstRecord
            }
            let encoded = try appendLocked(record, synchronize: true)
            let digest = SpikeSHA256.hexDigest(encoded)
            let result = (digest: digest, byteCount: UInt64(encoded.count))
            firstRecord = result
            return result
        }
    }

    private func appendLocked(
        _ record: SpikeMetricRecord,
        synchronize: Bool
    ) throws -> Data {
        guard !poisoned else {
            throw SpikeMetricError.evidenceWriterPoisoned
        }
        var encoded = try encoder.encode(record)
        encoded.append(0x0a)
        let originalOffset = try handle.offset()
        do {
            try handle.write(contentsOf: encoded)
            if synchronize {
                if let synchronizeHook {
                    try synchronizeHook()
                } else {
                    let result = SpikeDurability.synchronize(
                        descriptor: handle.fileDescriptor
                    )
                    if let failure = result.failure {
                        throw SpikeMetricError
                            .fileSynchronizeFailed(failure)
                    }
                    barrier = result.barrier
                }
                // Idempotent: only the first durable append creates directory
                // entries, so later synchronized appends do not pay for it.
                if !directoryEntriesSynchronized {
                    try synchronizeDirectoryEntriesLocked()
                    directoryEntriesSynchronized = true
                }
            }
        } catch {
            do {
                try handle.truncate(atOffset: originalOffset)
                try handle.seek(toOffset: originalOffset)
                try handle.synchronize()
            } catch {
                poisoned = true
                throw SpikeMetricError.evidenceWriterPoisoned
            }
            throw error
        }
        return encoded
    }

    /// Synchronizes every directory entry the evidence file depends on,
    /// parents before children, so a partially durable chain cannot be
    /// mistaken for a complete one.
    private func synchronizeDirectoryEntriesLocked() throws {
        for directory in directorySyncTargets {
            if let directorySynchronizeHook {
                try directorySynchronizeHook(directory)
                continue
            }
            let obtained: SpikeDurabilityBarrier
            if directory.standardizedFileURL.path == fileParent.path {
                let result = SpikeDurability.synchronize(
                    descriptor: parentDescriptor
                )
                if let failure = result.failure {
                    throw SpikeMetricError
                        .directorySynchronizeFailed(failure)
                }
                obtained = result.barrier
            } else {
                obtained = try SpikeDurability
                    .synchronizeDirectory(directory)
            }
            barrier = barrier.map { $0.combined(with: obtained) } ?? obtained
        }
    }

    private func withLock<T>(
        _ operation: () throws -> T
    ) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try operation()
    }
}

/// The only way for the provider to obtain a `ProviderStartAttestation`.
///
/// It cannot produce one without a durable first-record append, because the
/// attestation's memberwise initializers are not visible outside this module
/// and this is the sole public factory. A synchronize failure therefore fails
/// provider startup instead of yielding an attestation over an unflushed
/// record.
public enum ProviderStartAttestationRecorder {
    public static func recordFirstStartedRecord(
        writer: JSONLEvidenceWriter,
        record: SpikeMetricRecord,
        attemptNonce: String,
        requestedAtMonotonicNanoseconds: UInt64,
        providerReceivedAtMonotonicNanoseconds: UInt64,
        providerReadyClock: () -> UInt64
    ) throws -> ProviderStartAttestation {
        guard record.event == "started",
              record.startAttemptNonce == attemptNonce,
              record.startRequestedAtMonotonicNanoseconds ==
              requestedAtMonotonicNanoseconds,
              record.providerReceivedAtMonotonicNanoseconds ==
              providerReceivedAtMonotonicNanoseconds
        else {
            throw StartLatencyError.bindingMismatch("startedRecord")
        }
        let first = try writer.appendFirstRecordDurably(record)
        guard let durabilityBarrier = writer.durabilityBarrier else {
            throw SpikeMetricError.durabilityBarrierUnavailable
        }
        // Captured only after the durable append has returned, which is why
        // it cannot appear inside the record that was just hashed.
        let providerReady = providerReadyClock()
        return try ProviderStartAttestation(
            runID: record.runID,
            attemptNonce: attemptNonce,
            sourceDigest: record.sourceDigest,
            firstRecordSHA256: first.digest,
            firstRecordBytes: first.byteCount,
            evidenceDurabilityBarrier: durabilityBarrier.rawValue,
            requestedAtMonotonicNanoseconds:
                requestedAtMonotonicNanoseconds,
            providerReceivedAtMonotonicNanoseconds:
                providerReceivedAtMonotonicNanoseconds,
            providerReadyAtMonotonicNanoseconds: providerReady
        )
    }
}

/// A dependency-free SHA-256 used by Stage-A evidence persistence.
///
/// Keeping this implementation inside the Stage-A module prevents a
/// host-only diagnostic from acquiring CryptoKit merely because Swift links
/// another declaration from this source file. Existing golden comparisons
/// against CryptoKit in the test suite pin its behavior.
private enum SpikeSHA256 {
    private static let initial: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    private static let constants: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    static func hexDigest(_ data: Data) -> String {
        var bytes = [UInt8](data)
        let bitCount = UInt64(bytes.count) &* 8
        bytes.append(0x80)
        while bytes.count % 64 != 56 {
            bytes.append(0)
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: bitCount >> UInt64(shift)))
        }

        var hash = initial
        var words = [UInt32](repeating: 0, count: 64)
        for offset in stride(from: 0, to: bytes.count, by: 64) {
            for index in 0..<16 {
                let start = offset + index * 4
                words[index] =
                    UInt32(bytes[start]) << 24 |
                    UInt32(bytes[start + 1]) << 16 |
                    UInt32(bytes[start + 2]) << 8 |
                    UInt32(bytes[start + 3])
            }
            for index in 16..<64 {
                let previous15 = words[index - 15]
                let previous2 = words[index - 2]
                let sigma0 =
                    rotateRight(previous15, by: 7) ^
                    rotateRight(previous15, by: 18) ^
                    (previous15 >> 3)
                let sigma1 =
                    rotateRight(previous2, by: 17) ^
                    rotateRight(previous2, by: 19) ^
                    (previous2 >> 10)
                words[index] =
                    words[index - 16] &+ sigma0 &+
                    words[index - 7] &+ sigma1
            }

            var a = hash[0]
            var b = hash[1]
            var c = hash[2]
            var d = hash[3]
            var e = hash[4]
            var f = hash[5]
            var g = hash[6]
            var h = hash[7]

            for index in 0..<64 {
                let sum1 =
                    rotateRight(e, by: 6) ^
                    rotateRight(e, by: 11) ^
                    rotateRight(e, by: 25)
                let choice = (e & f) ^ ((~e) & g)
                let temporary1 =
                    h &+ sum1 &+ choice &+
                    constants[index] &+ words[index]
                let sum0 =
                    rotateRight(a, by: 2) ^
                    rotateRight(a, by: 13) ^
                    rotateRight(a, by: 22)
                let majority = (a & b) ^ (a & c) ^ (b & c)
                let temporary2 = sum0 &+ majority
                h = g
                g = f
                f = e
                e = d &+ temporary1
                d = c
                c = b
                b = a
                a = temporary1 &+ temporary2
            }

            hash[0] &+= a
            hash[1] &+= b
            hash[2] &+= c
            hash[3] &+= d
            hash[4] &+= e
            hash[5] &+= f
            hash[6] &+= g
            hash[7] &+= h
        }
        return hash.map { String(format: "%08x", $0) }.joined()
    }

    private static func rotateRight(
        _ value: UInt32,
        by amount: UInt32
    ) -> UInt32 {
        (value >> amount) | (value << (32 - amount))
    }
}
