import Foundation

/// Emits a Stage A JSONL run and its host activation receipt using the real
/// production types, so the Go verifiers check Swift's actual output rather
/// than a hand-written imitation of it.
///
/// In particular the first record is written through
/// `ProviderStartAttestationRecorder`, so the digest the receipt carries is
/// the one the provider would produce, and the Go side recomputes it from the
/// emitted bytes.
@main
enum SwiftEvidenceFixture {
    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 3 else {
            FileHandle.standardError.write(Data(
                "usage: swift-evidence-fixture <jsonl> <start-receipt>\n"
                    .utf8
            ))
            exit(2)
        }
        let evidenceURL = URL(fileURLWithPath: arguments[1])
        let receiptURL = URL(fileURLWithPath: arguments[2])
        let runID = "01234567-89ab-cdef-0123-456789abcdef"
        let attemptNonce = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        let requested: UInt64 = 900_000_000
        let providerReceived: UInt64 = 950_000_000
        let providerReady: UInt64 = 1_010_000_000
        let hostConnected: UInt64 = 1_050_000_000
        let source = String(repeating: "a", count: 64)
        let artifact = String(repeating: "b", count: 64)
        let resident: UInt64 = 12_000_000
        let energy: UInt64 = 50
        let active = 0
        let initialResource = SpikeResourceSnapshot(
            thermalState: "nominal",
            lowPowerMode: false
        )
        let window = SpikeResourceWindowSnapshot(
            firstSampleMonotonicNanoseconds: 31_000_000_000,
            lastSampleMonotonicNanoseconds: 61_000_000_000,
            sampleCount: 30,
            scheduledSampleCount: 30,
            peakResidentBytes: resident,
            peakPhysicalFootprintBytes: resident,
            minimumAvailableProcessBytes: nil,
            userCPUDeltaNanoseconds: energy,
            systemCPUDeltaNanoseconds: energy,
            interruptWakeupDelta: energy,
            packageIdleWakeupDelta: energy,
            energyDeltaNanojoules: energy,
            worstThermalState: "nominal",
            lowPowerModeObserved: false,
            lowPowerModeAlwaysEnabled: false
        )
        let wholeRunWindow = SpikeResourceWindowSnapshot(
            firstSampleMonotonicNanoseconds: 900_000_000,
            lastSampleMonotonicNanoseconds: 60_900_000_000,
            sampleCount: 61,
            scheduledSampleCount: 61,
            peakResidentBytes: resident,
            peakPhysicalFootprintBytes: resident,
            minimumAvailableProcessBytes: nil,
            userCPUDeltaNanoseconds: energy,
            systemCPUDeltaNanoseconds: energy,
            interruptWakeupDelta: energy,
            packageIdleWakeupDelta: energy,
            energyDeltaNanojoules: energy,
            worstThermalState: "nominal",
            lowPowerModeObserved: false,
            lowPowerModeAlwaysEnabled: false
        )
        let dataPath = SpikeDataPathSnapshot(
            allocatedPrivacyCellBytes: 2_097_152,
            inboundQueueDepth: 2,
            outboundQueueDepth: 2,
            inboundHighWatermark: 10,
            outboundHighWatermark: 10,
            occupancySamples: 6_000,
            inboundOccupancyP99Cells: 3,
            outboundOccupancyP99Cells: 3,
            acceptedCells: 6_120,
            emittedCells: 6_116,
            droppedCells: 0,
            retiredDataCells: 0,
            retiredCoverCells: 0,
            commonPathUnits: 6_000,
            commonPathActiveNanoseconds: 60_000_000_000,
            commonPathChecksum: 8_092_132_139_458_867_194,
            coverPairsAccepted: 60,
            coverInboundCellsAccepted: 60,
            coverOutboundCellsAccepted: 60,
            coverPairsEmitted: 59,
            coverInboundCellsEmitted: 59,
            coverOutboundCellsEmitted: 59,
            coverInboundCellsPending: 1,
            coverOutboundCellsPending: 1,
            coverInboundCellsRetired: 0,
            coverOutboundCellsRetired: 0,
            coverDeadlinesMissed: 0,
            maximumCoverLatenessNanoseconds: 10_000_000,
            queueDelaySamples: 6_116,
            queueDelayP99UpperBoundNanoseconds: 20_100_000,
            queueDelayOver25Milliseconds: 0,
            maximumObservedQueueDelayNanoseconds: 20_000_000,
            unaccountedWorkNanoseconds: 0,
            backpressureEvents: 0,
            backpressuredCells: 0,
            rotationCount: 0,
            maximumRotationOverlapNanoseconds: 0,
            rotationActiveCircuit: active,
            rotationStandbyCircuit: nil,
            rotationOverlapDeadlineNanoseconds: nil
        )
        let started = try SpikeMetricRecord(
            runID: runID,
            event: "started",
            monotonicNanoseconds: 1_000_000_000,
            wallTimeUTC: "2026-07-24T00:00:00.000Z",
            mode: .maximumPrivacy,
            trafficProfile: .low,
            coverSemantics: .continuousWhileConnected,
            rotationCadence: .protocolFifteenMinutes,
            durationNanoseconds: 60_000_000_000,
            trafficActiveNanoseconds: 60_000_000_000,
            sourceDigest: source,
            artifactDigest: artifact,
            resources: initialResource,
            startAttemptNonce: attemptNonce,
            startRequestedAtMonotonicNanoseconds: requested,
            providerReceivedAtMonotonicNanoseconds: providerReceived
        )
        let completed = try SpikeMetricRecord(
            runID: runID,
            event: "completed",
            monotonicNanoseconds: 61_000_000_000,
            wallTimeUTC: "2026-07-24T00:01:00.000Z",
            mode: .maximumPrivacy,
            trafficProfile: .low,
            coverSemantics: .continuousWhileConnected,
            rotationCadence: .protocolFifteenMinutes,
            durationNanoseconds: 60_000_000_000,
            trafficActiveNanoseconds: 60_000_000_000,
            sourceDigest: source,
            artifactDigest: artifact,
            resourceWindow: window,
            wholeRunResourceWindow: wholeRunWindow,
            dataPath: dataPath
        )

        let writer = try JSONLEvidenceWriter(fileURL: evidenceURL)
        let attestation = try ProviderStartAttestationRecorder
            .recordFirstStartedRecord(
                writer: writer,
                record: started,
                attemptNonce: attemptNonce,
                requestedAtMonotonicNanoseconds: requested,
                providerReceivedAtMonotonicNanoseconds: providerReceived,
                providerReadyClock: { providerReady }
            )
        try writer.append(completed, synchronize: true)

        // The host side is driven through the same state machine the app
        // uses, including the observer-before-start ordering.
        let attempt = try StartLatencyAttempt(attemptNonce: attemptNonce)
        try attempt.markObserverRegistered()
        _ = try attempt.startOptions(
            requestedAtMonotonicNanoseconds: requested
        )
        _ = try attempt.observeConnected(
            atMonotonicNanoseconds: hostConnected
        )
        let receipt = try attempt.hostStartReceipt(
            attestation: attestation,
            expectedSourceDigest: source
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var encoded = try encoder.encode(receipt)
        encoded.append(0x0a)
        try encoded.write(to: receiptURL, options: .withoutOverwriting)
    }
}
